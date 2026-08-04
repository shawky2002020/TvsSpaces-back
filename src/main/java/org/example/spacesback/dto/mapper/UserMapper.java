package org.example.spacesback.dto.mapper;

import org.example.spacesback.dto.response.UserResponse;
import org.example.spacesback.model.User;

public class UserMapper {
    public static UserResponse toUserResponse(User user) {
        if (user == null) {
            return null;
        }
        UserResponse response = new UserResponse();
        response.setId(user.getId());
        response.setUsername(user.getUsername());
        response.setEmail(user.getEmail());
        response.setType(user.getType());
        response.setRole(user.getRole());
        response.setCreationDate(user.getCreationDate());
        response.setLastLogin(user.getLastLogin());
        return response;
    }
}
