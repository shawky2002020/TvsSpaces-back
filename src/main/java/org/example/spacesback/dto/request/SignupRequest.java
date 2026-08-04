package org.example.spacesback.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.Locale;

@Data
public class SignupRequest {
    @NotBlank(message = "Name can't be empty")
    @Size(min = 3, max = 100, message = "Name must be between 3 and 100 characters")
    private String username;

    @NotBlank(message = "Email can't be empty")
    @Email(message = "Email format not correct")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    @Pattern(
            regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).*$",
            message = "Password must contain uppercase, lowercase, and number"
    )
    private String password;

    @NotBlank(message = "Type is required")
    @Pattern(
            regexp = "^(student|freelancer|entrepreneur|remote-worker|startup|other)$",
            message = "Invalid user type"
    )
    private String type;

    public void setUsername(String username) {
        this.username = username == null ? null : username.trim();
    }

    public void setEmail(String email) {
        this.email = email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
