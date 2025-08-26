package org.example.spacesback.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.example.spacesback.dto.request.LoginRequest;
import org.example.spacesback.dto.request.SignupRequest;
import org.example.spacesback.dto.response.JwtResponse;
import org.example.spacesback.model.User;
import org.example.spacesback.repository.UserRepository;
import org.example.spacesback.security.CustomUserDetails;
import org.example.spacesback.security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Optional;


@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final AuthenticationManager authManager;
    private final UserRepository userRepo;
    private final PasswordEncoder encoder;
    private final JwtUtil jwtUtil;

    public AuthController(AuthenticationManager authManager, UserRepository userRepo,
                          PasswordEncoder encoder, JwtUtil jwtUtil) {
        this.authManager = authManager;
        this.userRepo = userRepo;
        this.encoder = encoder;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest req) {
        if (userRepo.existsByEmail(req.getEmail())) return ResponseEntity.badRequest().body(Map.of("message","Email already registered"));
        User u = new User();
        u.setUsername(req.getUsername());
        u.setEmail(req.getEmail());
        u.setPassword(encoder.encode(req.getPassword()));
        u.setRole("ROLE_USER");
        u.setCreationDate(new Date());
        u.setLastLogin(new Date());
        u.setType(req.getType());
        userRepo.save(u);
        log.info("User logged in with email={}", u.getEmail());
        String newAccessToken = jwtUtil.generateToken(u.getEmail(), 15 * 60 * 1000);
        return ResponseEntity.ok(Map.of("token", newAccessToken, "user", u));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpServletResponse response) {
        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
            );
            Optional<User> userOptional = userRepo.findByEmail(req.getEmail());

            CustomUserDetails cud = (CustomUserDetails) auth.getPrincipal();
            if (userOptional.isEmpty()){
                return ResponseEntity.badRequest().body(Map.of("message","User Not Found"));
            }
            User user = userOptional.get();

            // Access token (short-lived, e.g., 15 min)
            String accessToken = jwtUtil.generateToken(cud.getEmail(), 15 * 60 * 1000);

            // Refresh token (longer-lived, e.g. 7 days)
            String refreshToken = jwtUtil.generateToken(cud.getEmail(), 7 * 24 * 60 * 60 * 1000);

            // Store refresh token in HttpOnly, Secure cookie
            ResponseCookie cookie = ResponseCookie.from("refresh_token", refreshToken)
                    .httpOnly(true)
                    .secure(false)              // ⚠️ use true only in prod/https
                    .path("/")
                    .maxAge(7 * 24 * 60 * 60)
                    .sameSite("Strict")
                    .build();

            response.addHeader("Set-Cookie", cookie.toString());
            user.setLoginCount(user.getLoginCount()+1);

            return ResponseEntity.ok(Map.of(
                    "message", "Login successful",
                    "token", accessToken,
                    "user", cud
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
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {
        // Extract refresh token from cookie
        String refreshToken = Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals("refresh_token"))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);

        if (refreshToken == null || !jwtUtil.isTokenValid(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }

        String email = jwtUtil.extractEmail(refreshToken);

        // Issue new access token
        String newAccessToken = jwtUtil.generateToken(email, 15 * 60 * 1000);

        return ResponseEntity.ok(Map.of("token", newAccessToken));
    }

}

