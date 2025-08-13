package org.example.spacesback.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class CustomAuthHandlers {

    // 401 Unauthorized handler
    @Component
    public static class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response,
                             org.springframework.security.core.AuthenticationException authException) throws IOException {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            Map<String, Object> body = new HashMap<>();
            body.put("status", 401);
            body.put("error", "Unauthorized");
            body.put("message", authException.getMessage());
            body.put("path", request.getRequestURI());

            new ObjectMapper().writeValue(response.getOutputStream(), body);
        }
    }

    // 403 Forbidden handler
    @Component
    public static class CustomAccessDeniedHandler implements AccessDeniedHandler {
        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response,
                           AccessDeniedException accessDeniedException) throws IOException {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);

            Map<String, Object> body = new HashMap<>();
            body.put("status", 403);
            body.put("error", "Forbidden");
            body.put("message", accessDeniedException.getMessage());
            body.put("path", request.getRequestURI());

            new ObjectMapper().writeValue(response.getOutputStream(), body);
        }
    }
}
