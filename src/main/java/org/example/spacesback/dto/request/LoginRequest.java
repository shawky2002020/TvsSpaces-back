package org.example.spacesback.dto.request;

import jakarta.validation.constraints.*;
import lombok.Data;

@Data
public class LoginRequest {

    @NotBlank(message = "Email can't be empty")
    @Email
    private String email;

    @NotBlank
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    @Pattern(
            regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).+$",
            message = "Password must contain uppercase, lowercase, number, and special character"
    )
    private String password;


}
