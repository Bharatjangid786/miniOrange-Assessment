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
    private JwtUtils jwtUtils;

    @Autowired
    private AuthService authService;

    @Autowired
    private RestTemplate restTemplate;

    private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    @GetMapping("/oauth2/callback")
    public ResponseEntity<?> handleOAuth2Callback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "error", required = false) String error
    ) {
        try {
            if (error != null) {
                return handleOAuthError(error);
            }

            if (code == null) {
                return ResponseEntity.badRequest().body("Missing authorization code.");
            }

            String accessToken = exchangeCodeForAccessToken(code);

            Map<String, Object> userInfo = fetchUserInfoFromGoogle(accessToken);


            String email = getUserEmail(userInfo);
            String name = getUserName(userInfo);


            Optional<User> existingUser = authService.findByEmail(email);
            if (existingUser.isEmpty()) {
                createUserInDB(name, email);
            }


            String jwt = jwtUtils.generateToken(email);


            return redirectToFrontendWithToken(jwt);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    private ResponseEntity<?> handleOAuthError(String error) {
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create("http://localhost:3000/login?error=" + error));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

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

        ResponseEntity<Map> response = restTemplate.postForEntity(
                "https://oauth2.googleapis.com/token", request, Map.class);

        return Objects.requireNonNull(response.getBody()).get("access_token").toString();
    }

    private Map<String, Object> fetchUserInfoFromGoogle(String accessToken) {
        HttpHeaders userHeaders = new HttpHeaders();
        userHeaders.setBearerAuth(accessToken);
        HttpEntity<String> userRequest = new HttpEntity<>(userHeaders);

        ResponseEntity<Map> userResponse = restTemplate.exchange(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                HttpMethod.GET,
                userRequest,
                Map.class
        );

        return userResponse.getBody();
    }

    private String getUserEmail(Map<String, Object> userInfo) {
        return userInfo.get("email") != null ? userInfo.get("email").toString() : "no-email@example.com";
    }

    private String getUserName(Map<String, Object> userInfo) {
        return userInfo.get("name") != null ? userInfo.get("name").toString() : "No Name";
    }

    private void createUserInDB(String name, String email) {
        authService.save(new User(name, email, passwordEncoder.encode(UUID.randomUUID().toString())));
    }

    private ResponseEntity<?> redirectToFrontendWithToken(String jwt) {
        String frontendRedirectUrl = "http://localhost:3000/dashboard?token=" + jwt;
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setLocation(URI.create(frontendRedirectUrl));
        return new ResponseEntity<>(httpHeaders, HttpStatus.FOUND);
    }
}
