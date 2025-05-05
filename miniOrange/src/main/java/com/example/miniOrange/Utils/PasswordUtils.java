package com.example.miniOrange.Utils;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordUtils {

    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public String hashPassword(String PlainPassword){
        return encoder.encode(PlainPassword); // Returns the hashed password
    }

    public Boolean isPasswordMatch(String rawPassword, String hashedPassword) {
        return encoder.matches(rawPassword, hashedPassword); // Returns true if matched
    }

}
