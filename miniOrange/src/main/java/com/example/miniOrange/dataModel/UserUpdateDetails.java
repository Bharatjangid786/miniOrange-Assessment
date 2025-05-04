package com.example.miniOrange.dataModel;

public class UserUpdateDetails {

    private String name;
    private String password;
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public UserUpdateDetails(String name, String password) {
        this.name = name;
        this.password = password;
    }
}
