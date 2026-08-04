package org.example.spacesback.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.spacesback.dto.request.UpdateUserRequest;
import org.example.spacesback.model.User;
import org.example.spacesback.repository.UserRepository;
import org.example.spacesback.repository.RefreshSessionRepository;
import org.example.spacesback.security.CustomUserDetails;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepo;
    private final RefreshSessionRepository refreshSessionRepo;
    private final PasswordEncoder passwordEncoder;

    @PatchMapping("/edit")
    @Transactional
    public ResponseEntity<?> editUser(@Valid @RequestBody UpdateUserRequest req, Authentication auth) {
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        Long idFromToken = userDetails.getId();
        Optional<User> optionalUser = userRepo.findById(idFromToken);

        if (optionalUser.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "User not found"));
        }

        User user = optionalUser.get();

        // Update email
        if (req.getEmail() != null && !req.getEmail().equalsIgnoreCase(user.getEmail())) {
            if (userRepo.existsByEmail(req.getEmail())) {
                return ResponseEntity.badRequest().body(Map.of("message", "Email already taken"));
            }
            String oldEmail = user.getEmail();
            user.setEmail(req.getEmail());
            // Sync refresh session
            refreshSessionRepo.findByEmail(oldEmail).ifPresent(session -> {
                session.setEmail(req.getEmail());
                refreshSessionRepo.save(session);
            });
        }

        if (req.getUsername() != null && !req.getUsername().equals(user.getUsername())) {
            user.setUsername(req.getUsername());
        }

        // Update password with old password verification
        if (req.getNewPassword() != null && !req.getNewPassword().isBlank()) {
            if (req.getCurrentPassword() == null || !passwordEncoder.matches(req.getCurrentPassword(), user.getPassword())) {
                return ResponseEntity.status(401).body(Map.of("message", "Incorrect or missing current password"));
            }
            user.setPassword(passwordEncoder.encode(req.getNewPassword()));
        }

        userRepo.save(user);

        return ResponseEntity.ok().body(Map.of("message", "User updated successfully"));
    }
}
