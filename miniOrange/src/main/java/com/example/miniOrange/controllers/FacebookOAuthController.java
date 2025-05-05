package com.example.miniOrange.controllers;

import com.example.miniOrange.dataModel.User;
import com.example.miniOrange.Utils.JwtUtils;
import com.example.miniOrange.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@RestController
public class FacebookOAuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtils jwtUtils;

    private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Value("${spring.security.oauth2.client.registration.facebook.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.facebook.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.facebook.redirect-uri}")
    private String redirectUri;

    @GetMapping("/oauth2/facebook/callback")
    public ResponseEntity<?> handleFacebookCallback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "error", required = false) String error
    ) {
        if (error != null) {
            return redirectToFrontend("http://localhost:3000/login?error=" + error);
        }

        if (code == null) {
            return ResponseEntity.badRequest().body("Missing authorization code");
        }

        try {
            RestTemplate restTemplate = new RestTemplate();

            String tokenUrl = String.format(
                    "https://graph.facebook.com/v15.0/oauth/access_token?client_id=%s&redirect_uri=%s&client_secret=%s&code=%s",
                    clientId, redirectUri, clientSecret, code
            );
            ResponseEntity<Map> tokenResponse = restTemplate.getForEntity(tokenUrl, Map.class);
            String accessToken = (String) Objects.requireNonNull(tokenResponse.getBody()).get("access_token");

            String userInfoUrl = String.format(
                    "https://graph.facebook.com/me?fields=id,name,email,picture&access_token=%s",
                    accessToken
            );
            ResponseEntity<Map> userInfoResponse = restTemplate.getForEntity(userInfoUrl, Map.class);
            Map<String, Object> userInfo = userInfoResponse.getBody();

            if (userInfo == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Unable to fetch user info");
            }

            String email = userInfo.getOrDefault("email", "no-email@example.com").toString();
            String name = userInfo.getOrDefault("name", "No Name").toString();

            Optional<User> existingUser = authService.findByEmail(email);
            if (existingUser.isEmpty()) {
                String randomPassword = passwordEncoder.encode(UUID.randomUUID().toString());
                authService.save(new User(name, email, randomPassword));
            }

            String jwtToken = jwtUtils.generateToken(email);

            return redirectToFrontend("http://localhost:3000/dashboard?token=" + jwtToken);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Facebook login failed");
        }
    }

    private ResponseEntity<?> redirectToFrontend(String url) {
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(url));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }
}