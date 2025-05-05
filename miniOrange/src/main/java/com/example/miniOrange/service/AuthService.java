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

    private Map<String, OtpDetails> otpStore = new HashMap<>();

    public Optional<User> findByEmail(String email) {
        return AuthRepo.findByEmail(email);
    }

    public Optional<User> findById(String id) {
        return AuthRepo.findById(id);
    }

    public String validateAndSendOtp(User signupRequest) {
        String email = signupRequest.getEmail();

        if (AuthRepo.existsByEmail(email)) {
            throw new IllegalArgumentException("User already exists");
        }

        return generateOtp(email);
    }

    private String generateOtp(String email) {
        int otp = ThreadLocalRandom.current().nextInt(100000, 1000000); // Generate a 6-digit OTP

        otpStore.put(email, new OtpDetails(otp, System.currentTimeMillis()));

        EmailService.sendEmail(email, "Your OTP Code", "Your OTP is: " + otp);

        return "OTP sent successfully to " + email;
    }

    public void save(User user) {
        AuthRepo.save(user);
    }

    private String completeSignup(User signupRequest) {
        String hashedPassword = PasswordUtils.hashPassword(signupRequest.getPassword());

        User newUser = new User(
                new ObjectId(), signupRequest.getName(), signupRequest.getEmail(), hashedPassword);

        AuthRepo.save(newUser);

        return "Signup completed successfully.";
    }

    public String verifyOtp(int enteredOtp, User signupRequest) {
        String email = signupRequest.getEmail();
        OtpDetails otpDetails = otpStore.get(email);

        if (otpDetails == null) {
            return "OTP not found or expired";
        }

        if (System.currentTimeMillis() - otpDetails.getTimestamp() > 5 * 60 * 1000) {
            otpStore.remove(email); // Remove expired OTP
            return "OTP expired";
        }

        if (otpDetails.getOtp() != enteredOtp) {
            return "Invalid OTP";
        }

        otpStore.remove(email);
        return "OTP Verified. " + completeSignup(signupRequest);
    }

    public ResponseEntity<?> authenticateUser(LoginDto loginDto) {
        try {
            User user = AuthRepo.findByEmail(loginDto.getEmail())
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));

            if (!PasswordUtils.isPasswordMatch(loginDto.getPassword(), user.getPassword())) {
                throw new IllegalArgumentException("Invalid credentials");
            }


            String jwtToken = JwtUtils.generateToken(user.getEmail());

            return ResponseEntity.ok(jwtToken);

        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Something went wrong");
        }
    }
}
