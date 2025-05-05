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


    @PutMapping("/update/{userId}")
    public ResponseEntity<?> userProfileUpdate(@PathVariable String userId, @RequestBody UserUpdateDetails updatedUser) {

        Optional<User> optionalUser = authService.findById(userId);

        if (optionalUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }

        User existingUser = optionalUser.get();

        existingUser.setName(updatedUser.getName());

        String hashPassword = passwordUtils.hashPassword(updatedUser.getPassword());
        existingUser.setPassword(hashPassword);

        authService.save(existingUser);

        return ResponseEntity.ok(existingUser);
    }


}
