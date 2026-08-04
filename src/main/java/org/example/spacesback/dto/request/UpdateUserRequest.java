package org.example.spacesback.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UpdateUserRequest {
    @Size(min = 3, max = 100, message = "Username must be between 3 and 100 characters")
    private String username;

    @Email(message = "Invalid email format")
    private String email;

    @Pattern(
            regexp = "^(student|freelancer|entrepreneur|remote-worker|startup|other)$",
            message = "Invalid user type"
    )
    private String type;

    private String currentPassword;

    @JsonProperty("password")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String newPassword;
}
