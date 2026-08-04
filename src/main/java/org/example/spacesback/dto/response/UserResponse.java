package org.example.spacesback.dto.response;

import lombok.Data;

import java.util.Date;

@Data
public class UserResponse {
    private Long id;
    private String username;
    private String email;
    private String type;
    private String role;
    private Date creationDate;
    private Date lastLogin;
}
