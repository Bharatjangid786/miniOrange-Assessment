package com.example.miniOrange.dataModel;

public class OtpRequest {
    private int otp;
    private User user;

    public int getOtp() {
        return otp;
    }

    public void setOtp(int otp) {
        this.otp = otp;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
