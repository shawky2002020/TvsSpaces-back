package org.example.spacesback.dto.request;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SignupRequest {
    @NotBlank(message = "Name can't be empty")
    private String username;

    @NotBlank(message = "Email can't be empty")
    @Email(message = "Email format not correct")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    @Pattern(
            regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).+$",
            message = "Password must contain uppercase, lowercase, number, and special character"
    )
    private String password;



}
