package org.example.spacesback.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtil {

    private final String SECRET = "yoursecretkeyyoursecretkeyyoursecretkey"; // >= 256 bits
    private final Key key = Keys.hmacShaKeyFor(SECRET.getBytes());

    public String extractEmail(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }



    public boolean isTokenValid(String token) {
        Date expiration = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        return expiration.after(new Date()); // true if still valid
    }

    public boolean validateToken(String token, CustomUserDetails cud) {
        String email = extractEmail(token);
        System.out.println("🔑 Extracted from token: " + email);
        System.out.println("👤 UserDetails email: " + cud.getEmail());

        boolean usernamesMatch = email.equals(cud.getEmail());
        System.out.println("✅ Usernames match? " + usernamesMatch);

        boolean tokenValid = isTokenValid(token);
        System.out.println("⏳ Token still valid? " + tokenValid);

        boolean result = usernamesMatch && tokenValid;
        System.out.println("🎯 Final validation result: " + result);

        return result;
    }




    public String generateToken(String username, Integer expirationMs) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
}
