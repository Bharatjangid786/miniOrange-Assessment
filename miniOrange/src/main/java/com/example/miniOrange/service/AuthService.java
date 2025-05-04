package com.example.miniOrange.service;
import com.example.miniOrange.dataModel.LoginDto;
import com.example.miniOrange.dataModel.OtpDetails;
import com.example.miniOrange.dataModel.User;
import com.example.miniOrange.Utils.JwtUtils;
import com.example.miniOrange.Utils.PasswordUtils;
import com.example.miniOrange.repository.authRepo;
import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;


@Service
public class AuthService {

    @Autowired
    private authRepo AuthRepo;

    @Autowired
    private PasswordUtils PasswordUtils;

    @Autowired
    private JwtUtils JwtUtils;

    @Autowired
    private EmailService EmailService;

    // Store OTPs temporarily for validation purposes
    private Map<String, OtpDetails> otpStore = new HashMap<>();

    // Find a user by email from the database
    public Optional<User> findByEmail(String email) {
        return AuthRepo.findByEmail(email);
    }

    // Find a user by their ID from the database
    public Optional<User> findById(String id) {
        return AuthRepo.findById(id);
    }

    // Validate the email during signup and send an OTP if valid
    public String validateAndSendOtp(User signupRequest) {
        String email = signupRequest.getEmail();

        // Check if the user already exists in the database
        if (AuthRepo.existsByEmail(email)) {
            throw new IllegalArgumentException("User already exists");
        }

        return generateOtp(email);  // Generate and send OTP if user does not exist
    }

    // Generate a unique OTP for the user and send it via email
    private String generateOtp(String email) {
        int otp = ThreadLocalRandom.current().nextInt(100000, 1000000); // Generate a 6-digit OTP

        // Store OTP with timestamp for expiration check
        otpStore.put(email, new OtpDetails(otp, System.currentTimeMillis()));

        // Send OTP email asynchronously
        EmailService.sendEmail(email, "Your OTP Code", "Your OTP is: " + otp);

        return "OTP sent successfully to " + email;
    }

    // Save a new user to the database
    public void save(User user) {
        AuthRepo.save(user);
    }

    // Complete the signup process by hashing the password and saving the user
    private String completeSignup(User signupRequest) {
        // Hash the password before saving to the database
        String hashedPassword = PasswordUtils.hashPassword(signupRequest.getPassword());

        // Create a new User object with the hashed password
        User newUser = new User(
                new ObjectId(), signupRequest.getName(), signupRequest.getEmail(), hashedPassword);

        AuthRepo.save(newUser); // Save the new user to the database

        return "Signup completed successfully.";
    }

    // Verify the OTP entered by the user and complete the signup process if valid
    public String verifyOtp(int enteredOtp, User signupRequest) {
        String email = signupRequest.getEmail();
        OtpDetails otpDetails = otpStore.get(email);

        // Check if OTP exists and is not expired
        if (otpDetails == null) {
            return "OTP not found or expired";
        }

        // Verify OTP expiration (5 minutes expiry time)
        if (System.currentTimeMillis() - otpDetails.getTimestamp() > 5 * 60 * 1000) {
            otpStore.remove(email); // Remove expired OTP
            return "OTP expired";
        }

        // Check if the entered OTP matches the stored OTP
        if (otpDetails.getOtp() != enteredOtp) {
            return "Invalid OTP";
        }

        otpStore.remove(email); // Remove the OTP after successful verification
        return "OTP Verified. " + completeSignup(signupRequest); // Proceed with signup after OTP verification
    }

    // Authenticate the user by verifying email and password, and generate a JWT token on success
    public ResponseEntity<?> authenticateUser(LoginDto loginDto) {
        try {
            // 1. Fetch the user by email
            User user = AuthRepo.findByEmail(loginDto.getEmail())
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));

            // 2. Verify the password
            if (!PasswordUtils.isPasswordMatch(loginDto.getPassword(), user.getPassword())) {
                throw new IllegalArgumentException("Invalid credentials");
            }

            // 3. Generate a JWT token if credentials are valid
            String jwtToken = JwtUtils.generateToken(user.getEmail());

            return ResponseEntity.ok(jwtToken); // Return JWT token on successful authentication

        } catch (IllegalArgumentException e) {
            // Return error response if user is not found or credentials are invalid
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace(); // Optional: Replace with logger
            // Return error response for any other exception
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Something went wrong");
        }
    }
}
