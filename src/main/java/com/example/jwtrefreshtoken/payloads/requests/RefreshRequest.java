package com.example.jwtrefreshtoken.payloads.requests;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class RefreshRequest {
    
    @NotNull(message = "refresh token cannot be null")
    @NotBlank(message = "refresh token cannot be blank")
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
