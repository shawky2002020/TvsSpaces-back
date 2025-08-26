package org.example.spacesback.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.spacesback.dto.request.UpdateUserRequest;
import org.example.spacesback.model.User;
import org.example.spacesback.repository.UserRepository;
import org.example.spacesback.security.CustomUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private static final Logger log = LoggerFactory.getLogger(UserController.class);


    @PatchMapping("/edit")
    public ResponseEntity<?> editUser(@Valid @RequestBody UpdateUserRequest req, Authentication auth) {
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        String emailFromToken = userDetails.getEmail();   // guaranteed email        System.out.println("emailfromtoken");
        System.out.println(emailFromToken);
        Optional<User> optionalUser = userRepo.findByEmail(emailFromToken);

        if (optionalUser.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "User not found"));
        }

        User user = optionalUser.get();


        // Update email
        if (req.getEmail() != null && !req.getEmail().equals(user.getEmail())) {
            if (userRepo.existsByEmail(req.getEmail())) {
                return ResponseEntity.badRequest().body(Map.of("message", "Email already taken"));
            }
            user.setEmail(req.getEmail());
        }
        if (req.getUsername() != null && !req.getUsername().equals(user.getUsername())) {
            user.setUsername(req.getUsername());
        }

        // Update password (⚠️ no old password check)
        if (req.getNewPassword() != null && !req.getNewPassword().isBlank()) {
            log.info("Entered newPassword: {} , email: {} , username: {}", req.getNewPassword(), req.getEmail(), req.getUsername());
            user.setPassword(passwordEncoder.encode(req.getNewPassword()));
        }

        userRepo.save(user);

        return ResponseEntity.ok().body(Map.of("message", "User updated successfully"));
    }
}
