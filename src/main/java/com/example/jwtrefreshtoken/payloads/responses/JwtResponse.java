package com.example.jwtrefreshtoken.payloads.responses;

public class JwtResponse {
    private String accessToken;

    private String refreshToken;

    public JwtResponse() {}

    public JwtResponse(String accessTplen, String refreshToken) {
        this.accessToken = accessTplen;
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
