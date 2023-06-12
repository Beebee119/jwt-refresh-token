package com.example.jwtrefreshtoken.payloads.requests;

import javax.validation.constraints.NotBlank;

public class RefreshRequest {
    
    @NotBlank
    private String refreshToken;

    public RefreshRequest() {}

    public RefreshRequest(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
