package org.example.spacesback.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.example.spacesback.dto.request.LoginRequest;
import org.example.spacesback.dto.request.SignupRequest;
import org.example.spacesback.dto.response.UserResponse;
import org.example.spacesback.dto.mapper.UserMapper;
import org.example.spacesback.model.User;
import org.example.spacesback.model.RefreshSession;
import org.example.spacesback.repository.UserRepository;
import org.example.spacesback.repository.RefreshSessionRepository;
import org.example.spacesback.security.CustomUserDetails;
import org.example.spacesback.security.JwtUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authManager;
    private final UserRepository userRepo;
    private final RefreshSessionRepository refreshSessionRepo;
    private final PasswordEncoder encoder;
    private final JwtUtil jwtUtil;

    @Value("${app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${app.jwtRefreshExpirationMs}")
    private int jwtRefreshExpirationMs;

    @Value("${app.cookieSecure}")
    private boolean cookieSecure;

    @Value("${app.cookieSameSite}")
    private String cookieSameSite;

    public AuthController(AuthenticationManager authManager, UserRepository userRepo,
                          RefreshSessionRepository refreshSessionRepo, PasswordEncoder encoder, JwtUtil jwtUtil) {
        this.authManager = authManager;
        this.userRepo = userRepo;
        this.refreshSessionRepo = refreshSessionRepo;
        this.encoder = encoder;
        this.jwtUtil = jwtUtil;
    }

    private String hashToken(String token) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error hashing token", e);
        }
    }

    private void saveRefreshSession(String email, String token, long durationMs) {
        RefreshSession session = refreshSessionRepo.findByEmail(email).orElse(new RefreshSession());
        session.setEmail(email);
        session.setTokenHash(hashToken(token));
        session.setExpiryDate(new Date(System.currentTimeMillis() + durationMs));
        refreshSessionRepo.save(session);
    }

    @PostMapping("/signup")
    @Transactional
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest req, HttpServletResponse response) {
        if (userRepo.existsByEmail(req.getEmail())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Email already registered"));
        }
        User u = new User();
        u.setUsername(req.getUsername());
        u.setEmail(req.getEmail());
        u.setPassword(encoder.encode(req.getPassword()));
        u.setRole("ROLE_USER");
        u.setCreationDate(new Date());
        u.setLastLogin(new Date());
        u.setType(req.getType());
        u.setLoginCount(1);
        userRepo.save(u);

        String accessToken = jwtUtil.generateToken(u.getId(), jwtExpirationMs, "access");
        String refreshToken = jwtUtil.generateToken(u.getId(), jwtRefreshExpirationMs, "refresh");

        saveRefreshSession(u.getEmail(), refreshToken, jwtRefreshExpirationMs);

        ResponseCookie cookie = ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(jwtRefreshExpirationMs / 1000)
                .sameSite(cookieSameSite)
                .build();

        response.addHeader("Set-Cookie", cookie.toString());

        return ResponseEntity.ok(Map.of(
                "token", accessToken,
                "user", UserMapper.toUserResponse(u)
        ));
    }

    @PostMapping("/login")
    @Transactional
    public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpServletResponse response) {
        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
            );
            Optional<User> userOptional = userRepo.findByEmail(req.getEmail());

            if (userOptional.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("message", "User Not Found"));
            }
            User user = userOptional.get();

            // Access token
            String accessToken = jwtUtil.generateToken(user.getId(), jwtExpirationMs, "access");

            // Refresh token
            String refreshToken = jwtUtil.generateToken(user.getId(), jwtRefreshExpirationMs, "refresh");

            // Save refresh session
            saveRefreshSession(user.getEmail(), refreshToken, jwtRefreshExpirationMs);

            // Store refresh token in HttpOnly cookie
            ResponseCookie cookie = ResponseCookie.from("refresh_token", refreshToken)
                    .httpOnly(true)
                    .secure(cookieSecure)
                    .path("/")
                    .maxAge(jwtRefreshExpirationMs / 1000)
                    .sameSite(cookieSameSite)
                    .build();

            response.addHeader("Set-Cookie", cookie.toString());

            user.setLoginCount(user.getLoginCount() + 1);
            user.setLastLogin(new Date());
            userRepo.save(user);

            return ResponseEntity.ok(Map.of(
                    "message", "Login successful",
                    "token", accessToken,
                    "user", UserMapper.toUserResponse(user)
            ));

        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid email or password"));
        } catch (LockedException ex) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("message", "Account is locked"));
        } catch (DisabledException ex) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("message", "Account is disabled"));
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Authentication failed"));
        }
    }

    @PostMapping("/refresh")
    @Transactional
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {
        if (request.getCookies() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Cookies are missing"));
        }

        String refreshToken = Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals("refresh_token"))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);

        if (refreshToken == null || jwtUtil.isTokenExpired(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Invalid or expired refresh token"));
        }

        String subject = jwtUtil.extractSubject(refreshToken);
        String tokenType = jwtUtil.extractTokenType(refreshToken);
        if (subject == null || !"refresh".equals(tokenType)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Invalid token type"));
        }

        Long userId = Long.valueOf(subject);
        User user = userRepo.findById(userId).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "User not found"));
        }

        Optional<RefreshSession> sessionOpt = refreshSessionRepo.findByEmail(user.getEmail());
        if (sessionOpt.isEmpty() || !sessionOpt.get().getTokenHash().equals(hashToken(refreshToken)) || sessionOpt.get().getExpiryDate().before(new Date())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Refresh session has expired or is invalid"));
        }

        String newAccessToken = jwtUtil.generateToken(user.getId(), jwtExpirationMs, "access");

        return ResponseEntity.ok(Map.of("token", newAccessToken));
    }

    @PostMapping("/logout")
    @Transactional
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        if (request.getCookies() != null) {
            Arrays.stream(request.getCookies())
                    .filter(c -> c.getName().equals("refresh_token"))
                    .findFirst()
                    .ifPresent(c -> {
                        String subject = jwtUtil.extractSubject(c.getValue());
                        if (subject != null) {
                            try {
                                Long userId = Long.valueOf(subject);
                                userRepo.findById(userId).ifPresent(user -> {
                                    refreshSessionRepo.deleteByEmail(user.getEmail());
                                });
                            } catch (Exception e) {
                                // Ignore
                            }
                        }
                    });
        }

        ResponseCookie cookie = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(0)
                .sameSite(cookieSameSite)
                .build();

        response.addHeader("Set-Cookie", cookie.toString());

        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}
