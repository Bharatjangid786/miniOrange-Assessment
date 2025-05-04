package com.example.miniOrange.Utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtils {

    // Inject the secret key from application.properties
    @Value("${spring.secret.key}")
    private String SECRET_KEY;

    // Generate a signing key using HMAC-SHA algorithm from the secret key
    private SecretKey getSignkey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    // Generate a JWT token for a given email (subject)
    public String generateToken(String email) {
        Map<String, Object> tokenClaims = new HashMap<>();
        return createToken(tokenClaims, email);
    }

    // Helper method to create the JWT token with claims and subject (email)
    private String createToken(Map<String, Object> tokenClaims, String subject) {
        return Jwts.builder()
                .claims(tokenClaims) // Custom claims (empty in this case)
                .subject(subject)    // Subject of the token (usually email or username)
                .header().add("typ", "JWT") // Set header type to JWT
                .and()
                .issuedAt(new Date(System.currentTimeMillis())) // Token issued time
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // Token expires in 1 hour
                .signWith(getSignkey()) // Sign the token with secret key
                .compact(); // Build the final token string
    }

    // Extract email (subject) from the token
    public String extractEmail(String token) {
        return extractAllClaims(token).getSubject();
    }

    // Extract expiration date from the token
    public Date extractExpiration(String token) {
        return extractAllClaims(token).getExpiration();
    }

    // Validate the token: returns true if valid and not expired
    public boolean validateToken(String token) {
        try {
            return !isTokenExpired(token); // Valid if not expired
        } catch (JwtException | IllegalArgumentException e) {
            return false; // Invalid token
        }
    }

    // Check if the token is expired
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Extract all claims from the JWT token
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignkey()) // Use secret key to validate the signature
                .build()
                .parseSignedClaims(token) // Parse the signed JWT
                .getPayload(); // Get the claims (payload)
    }
}
