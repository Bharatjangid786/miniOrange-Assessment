package com.example.miniOrange.controllers;

import com.example.miniOrange.dataModel.User;
//import com.example.miniOrange.jwtUtils.JwtUtils;
//import com.example.miniOrange.service.AuthService;
import com.example.miniOrange.Utils.JwtUtils;
import com.example.miniOrange.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@RestController
public class GoogleOAuthController {

    // Autowired dependencies
    @Autowired
    private JwtUtils jwtUtils;  // Utility to generate JWT

    @Autowired
    private AuthService authService;  // Service to handle authentication logic

    @Autowired
    private RestTemplate restTemplate;  // RestTemplate to make HTTP requests

    // Password encoder for encoding passwords
    private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    // Properties from application configuration
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    //This method handles the OAuth2 callback from Google after successful authentication
    @GetMapping("/oauth2/callback")
    public ResponseEntity<?> handleOAuth2Callback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "error", required = false) String error
    ) {
        try {
            // Handle the case where there's an error in the OAuth2 process
            if (error != null) {
                return handleOAuthError(error); // Redirect user to login with error message
            }

            // If the authorization code is not present, return a bad request error
            if (code == null) {
                return ResponseEntity.badRequest().body("Missing authorization code.");
            }

            // Exchange the authorization code for an access token from Google
            String accessToken = exchangeCodeForAccessToken(code);

            // Fetch user information from Google using the access token
            Map<String, Object> userInfo = fetchUserInfoFromGoogle(accessToken);

            // Get the email and name from the user's information (with default values)
            String email = getUserEmail(userInfo);
            String name = getUserName(userInfo);

            // Check if the user exists in the database, if not, create a new user
            Optional<User> existingUser = authService.findByEmail(email);
            if (existingUser.isEmpty()) {
                createUserInDB(name, email);
            }

            // Generate a JWT for the authenticated user
            String jwt = jwtUtils.generateToken(email);

            // Redirect the user to the frontend with the JWT token
            return redirectToFrontendWithToken(jwt);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // Helper method to handle errors during the OAuth2 process
    private ResponseEntity<?> handleOAuthError(String error) {
        HttpHeaders headers = new HttpHeaders();
        // Redirect user to the frontend login page with error message
        headers.setLocation(URI.create("http://localhost:3000/login?error=" + error));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    // Helper method to exchange the authorization code for an access token
    private String exchangeCodeForAccessToken(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("redirect_uri", redirectUri);
        params.add("grant_type", "authorization_code");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        // Make the request to Google for the access token
        ResponseEntity<Map> response = restTemplate.postForEntity(
                "https://oauth2.googleapis.com/token", request, Map.class);

        // Extract and return the access token from the response
        return Objects.requireNonNull(response.getBody()).get("access_token").toString();
    }

    // Helper method to fetch the user's information from Google using the access token
    private Map<String, Object> fetchUserInfoFromGoogle(String accessToken) {
        HttpHeaders userHeaders = new HttpHeaders();
        userHeaders.setBearerAuth(accessToken);  // Set Authorization header with the access token
        HttpEntity<String> userRequest = new HttpEntity<>(userHeaders);

        // Make the GET request to fetch user info
        ResponseEntity<Map> userResponse = restTemplate.exchange(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                HttpMethod.GET,
                userRequest,
                Map.class
        );

        return userResponse.getBody();
    }

    // Helper method to extract the email from the user info
    private String getUserEmail(Map<String, Object> userInfo) {
        return userInfo.get("email") != null ? userInfo.get("email").toString() : "no-email@example.com";
    }

    // Helper method to extract the name from the user info
    private String getUserName(Map<String, Object> userInfo) {
        return userInfo.get("name") != null ? userInfo.get("name").toString() : "No Name";
    }

    // Helper method to create a new user in the database
    private void createUserInDB(String name, String email) {
        // Save the new user with a random password (since it's OAuth login, password is not needed)
        authService.save(new User(name, email, passwordEncoder.encode(UUID.randomUUID().toString())));
    }

    // Helper method to generate the JWT token and redirect the user to the frontend
    private ResponseEntity<?> redirectToFrontendWithToken(String jwt) {
        String frontendRedirectUrl = "http://localhost:3000/dashboard?token=" + jwt;
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setLocation(URI.create(frontendRedirectUrl));
        return new ResponseEntity<>(httpHeaders, HttpStatus.FOUND);
    }
}
