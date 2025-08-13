package org.example.spacesback.dto.response;

import lombok.Data;

@Data
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private String username;

public JwtResponse(String token, String type, String username) {
    this.token = token;
    this.type = type;
    this.username = username;
}


}
