package com.example.miniOrange.Utils;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordUtils {

    // Create a single instance of BCryptPasswordEncoder (used for hashing and verifying passwords)
    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    // Method to hash a plain text password using BCrypt algorithm
    public String hashPassword(String PlainPassword){
        return encoder.encode(PlainPassword); // Returns the hashed password
    }

    // Method to verify if the raw (plain text) password matches the hashed password
    public Boolean isPasswordMatch(String rawPassword, String hashedPassword) {
        return encoder.matches(rawPassword, hashedPassword); // Returns true if matched
    }

}
