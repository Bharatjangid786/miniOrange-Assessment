package com.example.miniOrange.controllers;



import com.example.miniOrange.dataModel.LoginDto;
import com.example.miniOrange.dataModel.OtpRequest;
import com.example.miniOrange.dataModel.User;
import com.example.miniOrange.Utils.JwtUtils;
import com.example.miniOrange.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/auth")
public class AuthController {


    @Autowired
    private JwtUtils JwtUtils;

    @Autowired
    private AuthService AuthService;

    @PostMapping("/signUp")
     public ResponseEntity<String> signup(@RequestBody User signUpRequest){
        try {
            return ResponseEntity.ok(AuthService.validateAndSendOtp(signUpRequest));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }


    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestBody OtpRequest otpRequest){
        User signupRequest = otpRequest.getUser();
        if (signupRequest == null) {
            return "User data is missing in the request";
        }
       return AuthService.verifyOtp(otpRequest.getOtp(), otpRequest.getUser());
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginDto loginRequest) {
        return AuthService.authenticateUser(loginRequest);
    }

    @PostMapping("/verify-token")
    public ResponseEntity<?> verifyToken(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        // Check if the Authorization header is present and starts with "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Missing or invalid Authorization header"));
        }

        String token = authHeader.substring(7);

        if (!JwtUtils.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid or expired token"));
        }

        String email = JwtUtils.extractEmail(token);

        return ResponseEntity.ok(Map.of(
                "email", email,
                "message", "Token is valid"
        ));
    }


}
