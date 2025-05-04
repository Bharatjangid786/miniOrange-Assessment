package com.example.miniOrange.dataModel;

// DTO class to hold login request data
public class LoginDto {

    private String email;
    private String password;

    public LoginDto() {
        // Default constructor (required for deserialization)
    }

    public LoginDto(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
