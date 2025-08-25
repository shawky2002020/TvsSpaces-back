package org.example.spacesback.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.spacesback.dto.request.UpdateUserRequest;
import org.example.spacesback.model.User;
import org.example.spacesback.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;



    @PatchMapping("/edit")
    public ResponseEntity<?> editUser(@Valid @RequestBody UpdateUserRequest req, Authentication auth) {
        String emailFromToken = auth.getName(); // from JWT
        Optional<User> optionalUser = userRepo.findByEmail(emailFromToken);

        if (optionalUser.isEmpty()) {
            return ResponseEntity.badRequest().body("User not found");
        }

        User user = optionalUser.get();

        // Update username
        if (req.getUsername() != null && !req.getUsername().isBlank()) {
            if (userRepo.existsByUsername(req.getUsername()) && !req.getUsername().equals(user.getUsername())) {
                return ResponseEntity.badRequest().body("Username already taken");
            }
            user.setUsername(req.getUsername());
        }

        // Update email
        if (req.getEmail() != null && !req.getEmail().equals(user.getEmail())) {
            if (userRepo.existsByEmail(req.getEmail())) {
                return ResponseEntity.badRequest().body("Email already taken");
            }
            user.setEmail(req.getEmail());
        }

        // Update password (⚠️ no old password check)
        if (req.getNewPassword() != null && !req.getNewPassword().isBlank()) {
            user.setPassword(passwordEncoder.encode(req.getNewPassword()));
        }

        userRepo.save(user);

        return ResponseEntity.ok("User updated successfully");
    }
}
