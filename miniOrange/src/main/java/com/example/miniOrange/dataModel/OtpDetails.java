package com.example.miniOrange.dataModel;

    public class OtpDetails {
        private int otp;
        private long timestamp;
        public int getOtp() {
            return otp;
        }

        public void setOtp(int otp) {
            this.otp = otp;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public void setTimestamp(long timestamp) {
            this.timestamp = timestamp;
        }

        public OtpDetails(int otp, long timestamp) {
            this.otp = otp;
            this.timestamp = timestamp;
        }

    }

