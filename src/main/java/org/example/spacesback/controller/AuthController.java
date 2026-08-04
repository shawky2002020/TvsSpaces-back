package org.example.spacesback.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.example.spacesback.dto.mapper.UserMapper;
import org.example.spacesback.dto.request.LoginRequest;
import org.example.spacesback.dto.request.SignupRequest;
import org.example.spacesback.model.RefreshSession;
import org.example.spacesback.model.User;
import org.example.spacesback.repository.RefreshSessionRepository;
import org.example.spacesback.repository.UserRepository;
import org.example.spacesback.security.JwtUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String REFRESH_COOKIE = "refresh_token";

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

    public AuthController(
            AuthenticationManager authManager,
            UserRepository userRepo,
            RefreshSessionRepository refreshSessionRepo,
            PasswordEncoder encoder,
            JwtUtil jwtUtil
    ) {
        this.authManager = authManager;
        this.userRepo = userRepo;
        this.refreshSessionRepo = refreshSessionRepo;
        this.encoder = encoder;
        this.jwtUtil = jwtUtil;
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to hash refresh token", exception);
        }
    }

    private void saveRefreshSession(User user, String token) {
        RefreshSession session = refreshSessionRepo.findByEmail(user.getEmail())
                .orElseGet(RefreshSession::new);
        session.setEmail(user.getEmail());
        session.setTokenHash(hashToken(token));
        session.setExpiryDate(new Date(System.currentTimeMillis() + jwtRefreshExpirationMs));
        refreshSessionRepo.save(session);
    }

    private void addRefreshCookie(HttpServletResponse response, String token, long maxAgeSeconds) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE, token)
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(maxAgeSeconds)
                .sameSite(cookieSameSite)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    private Map<String, Object> createSessionResponse(User user, HttpServletResponse response) {
        String accessToken = jwtUtil.generateToken(user.getId(), jwtExpirationMs, "access");
        String refreshToken = jwtUtil.generateToken(user.getId(), jwtRefreshExpirationMs, "refresh");
        saveRefreshSession(user, refreshToken);
        addRefreshCookie(response, refreshToken, jwtRefreshExpirationMs / 1000L);

        return Map.of(
                "token", accessToken,
                "user", UserMapper.toUserResponse(user)
        );
    }

    @PostMapping("/signup")
    @Transactional
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest req, HttpServletResponse response) {
        if (userRepo.existsByEmail(req.getEmail())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Email already registered"));
        }

        User user = new User();
        user.setUsername(req.getUsername());
        user.setEmail(req.getEmail());
        user.setPassword(encoder.encode(req.getPassword()));
        user.setRole("ROLE_USER");
        user.setCreationDate(new Date());
        user.setLastLogin(new Date());
        user.setType(req.getType());
        user.setLoginCount(1);
        userRepo.save(user);

        return ResponseEntity.status(HttpStatus.CREATED).body(createSessionResponse(user, response));
    }

    @PostMapping("/login")
    @Transactional
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req, HttpServletResponse response) {
        try {
            authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
            );

            User user = userRepo.findByEmail(req.getEmail()).orElse(null);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Invalid email or password"));
            }

            user.setLoginCount(user.getLoginCount() + 1);
            user.setLastLogin(new Date());
            userRepo.save(user);

            Map<String, Object> body = new java.util.HashMap<>(createSessionResponse(user, response));
            body.put("message", "Login successful");
            return ResponseEntity.ok(body);
        } catch (BadCredentialsException exception) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid email or password"));
        } catch (LockedException exception) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("message", "Account is locked"));
        } catch (DisabledException exception) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("message", "Account is disabled"));
        } catch (AuthenticationException exception) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Authentication failed"));
        }
    }

    @PostMapping("/refresh")
    @Transactional
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = getRefreshToken(request);
        if (refreshToken == null || jwtUtil.isTokenExpired(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid or expired refresh token"));
        }

        String subject = jwtUtil.extractSubject(refreshToken);
        String tokenType = jwtUtil.extractTokenType(refreshToken);
        if (subject == null || !"refresh".equals(tokenType)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid refresh token"));
        }

        Long userId;
        try {
            userId = Long.valueOf(subject);
        } catch (NumberFormatException exception) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid refresh token"));
        }

        User user = userRepo.findById(userId).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "User not found"));
        }

        RefreshSession session = refreshSessionRepo.findByEmail(user.getEmail()).orElse(null);
        if (session == null
                || !MessageDigest.isEqual(
                        session.getTokenHash().getBytes(StandardCharsets.UTF_8),
                        hashToken(refreshToken).getBytes(StandardCharsets.UTF_8)
                )
                || session.getExpiryDate().before(new Date())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Refresh session has expired or is invalid"));
        }

        String newAccessToken = jwtUtil.generateToken(user.getId(), jwtExpirationMs, "access");
        String newRefreshToken = jwtUtil.generateToken(user.getId(), jwtRefreshExpirationMs, "refresh");
        saveRefreshSession(user, newRefreshToken);
        addRefreshCookie(response, newRefreshToken, jwtRefreshExpirationMs / 1000L);

        return ResponseEntity.ok(Map.of("token", newAccessToken));
    }

    @PostMapping("/logout")
    @Transactional
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = getRefreshToken(request);
        String subject = refreshToken == null ? null : jwtUtil.extractSubject(refreshToken);

        if (subject != null) {
            try {
                Long userId = Long.valueOf(subject);
                userRepo.findById(userId)
                        .ifPresent(user -> refreshSessionRepo.deleteByEmail(user.getEmail()));
            } catch (NumberFormatException ignored) {
                // Invalid cookies are still cleared below.
            }
        }

        addRefreshCookie(response, "", 0);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    private String getRefreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;

        return Arrays.stream(cookies)
                .filter(cookie -> REFRESH_COOKIE.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}
