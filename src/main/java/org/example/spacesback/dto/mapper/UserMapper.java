package org.example.spacesback.dto.mapper;

import org.example.spacesback.dto.response.UserResponse;
import org.example.spacesback.model.User;

public class UserMapper {
    public static UserResponse toUserResponse(User user) {
        UserResponse response = new UserResponse();
        response.setId(user.getId());
        response.setUsername(user.getUsername());
        response.setEmail(user.getEmail());
        return response;
    }
}
