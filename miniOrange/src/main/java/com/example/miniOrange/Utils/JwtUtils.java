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

    @Value("${spring.secret.key}")
    private String SECRET_KEY;

    private SecretKey getSignkey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    public String generateToken(String email) {
        Map<String, Object> tokenClaims = new HashMap<>();
        return createToken(tokenClaims, email);
    }

    private String createToken(Map<String, Object> tokenClaims, String subject) {
        return Jwts.builder()
                .claims(tokenClaims)
                .subject(subject)
                .header().add("typ", "JWT")
                .and()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .signWith(getSignkey())
                .compact();
    }

    public String extractEmail(String token) {
        return extractAllClaims(token).getSubject();
    }

    public Date extractExpiration(String token) {
        return extractAllClaims(token).getExpiration();
    }

    public boolean validateToken(String token) {
        try {
            return !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }


    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignkey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
