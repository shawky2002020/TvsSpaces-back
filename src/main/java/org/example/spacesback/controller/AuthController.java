package org.example.spacesback.controller;

import jakarta.validation.Valid;
import org.example.spacesback.dto.request.LoginRequest;
import org.example.spacesback.dto.request.SignupRequest;
import org.example.spacesback.dto.response.JwtResponse;
import org.example.spacesback.model.User;
import org.example.spacesback.repository.UserRepository;
import org.example.spacesback.security.JwtUtil;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Date;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
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
        if (userRepo.existsByEmail(req.getEmail())) return ResponseEntity.badRequest().body("email taken");
        User u = new User();
        u.setUsername(req.getUsername());
        u.setEmail(req.getEmail());
        u.setPassword(encoder.encode(req.getPassword()));
        u.setRole("ROLE_USER");
        u.setCreationDate(new Date());
        u.setLastLogin(new Date());
        userRepo.save(u);
        return ResponseEntity.ok("user registered");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
        Optional<User> u = userRepo.findByEmail(req.getEmail());
        u.ifPresent(user ->
                {
                    user.setLastLogin(new Date());
                    userRepo.save(u.get());
                }
        );
        UserDetails ud = (UserDetails) auth.getPrincipal();
        String token = jwtUtil.generateToken(ud.getUsername());
        return ResponseEntity.ok(new JwtResponse(token, "Bearer", ud.getUsername()));
    }
}
