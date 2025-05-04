package com.example.miniOrange.controllers;
import com.example.miniOrange.dataModel.User;
import com.example.miniOrange.dataModel.UserUpdateDetails;
import com.example.miniOrange.Utils.PasswordUtils;
import com.example.miniOrange.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

//@Component
@CrossOrigin("*")
@RestController
@RequestMapping("/user")

public class UserController {

    @Autowired
    private AuthService authService;

    @Autowired
    private PasswordUtils passwordUtils;

    @GetMapping("/profile/{email}")
    public ResponseEntity<?> getProfile(@PathVariable String email) {
        User user = authService.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return ResponseEntity.ok(user);
    }


    @PutMapping("/update/{userId}") // Endpoint to update user profile using HTTP PUT method
    public ResponseEntity<?> userProfileUpdate(@PathVariable String userId, @RequestBody UserUpdateDetails updatedUser) {

        // Attempt to find the user by their ID
        Optional<User> optionalUser = authService.findById(userId);

        // If the user does not exist, return 404 Not Found
        if (optionalUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }

        // Retrieve the existing user object
        User existingUser = optionalUser.get();

        // Update the user's name with the new name from request
        existingUser.setName(updatedUser.getName());

        // Securely hash the new password before saving
        String hashPassword = passwordUtils.hashPassword(updatedUser.getPassword());
        existingUser.setPassword(hashPassword);

        // Save the updated user object to the database
        authService.save(existingUser);

        // Return the updated user details in the response with status 200 OK
        return ResponseEntity.ok(existingUser);
    }


}
