package org.example.spacesback.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.spacesback.dto.mapper.UserMapper;
import org.example.spacesback.dto.request.UpdateUserRequest;
import org.example.spacesback.model.User;
import org.example.spacesback.repository.RefreshSessionRepository;
import org.example.spacesback.repository.UserRepository;
import org.example.spacesback.security.CustomUserDetails;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Locale;
import java.util.Map;

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
        User user = userRepo.findById(userDetails.getId()).orElse(null);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", "User not found"));
        }

        if (req.getEmail() != null && !req.getEmail().isBlank()) {
            String normalizedEmail = req.getEmail().trim().toLowerCase(Locale.ROOT);
            if (!normalizedEmail.equalsIgnoreCase(user.getEmail())) {
                if (userRepo.existsByEmail(normalizedEmail)) {
                    return ResponseEntity.badRequest().body(Map.of("message", "Email already taken"));
                }
                String oldEmail = user.getEmail();
                user.setEmail(normalizedEmail);
                refreshSessionRepo.findByEmail(oldEmail).ifPresent(session -> {
                    session.setEmail(normalizedEmail);
                    refreshSessionRepo.save(session);
                });
            }
        }

        if (req.getUsername() != null && !req.getUsername().isBlank()) {
            user.setUsername(req.getUsername().trim());
        }

        if (req.getNewPassword() != null && !req.getNewPassword().isBlank()) {
            if (req.getCurrentPassword() == null
                    || !passwordEncoder.matches(req.getCurrentPassword(), user.getPassword())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Incorrect or missing current password"));
            }
            user.setPassword(passwordEncoder.encode(req.getNewPassword()));
        }

        User savedUser = userRepo.save(user);
        return ResponseEntity.ok(Map.of(
                "message", "User updated successfully",
                "user", UserMapper.toUserResponse(savedUser)
        ));
    }
}
