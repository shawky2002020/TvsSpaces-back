package org.example.spacesback.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.example.spacesback.controller.AuthController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Data
public class UpdateUserRequest {
    @Size(min = 3, max = 30, message = "Username must be between 3 and 30 characters")
    private String username;

    @Email(message = "Invalid email format")
    private String email;

    @JsonProperty("password")
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String newPassword;
}
