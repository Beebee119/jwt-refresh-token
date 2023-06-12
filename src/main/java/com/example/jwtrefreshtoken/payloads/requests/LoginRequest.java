package com.example.jwtrefreshtoken.payloads.requests;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class LoginRequest {
    @NotNull(message = "username cannot be null")
    @NotBlank(message = "username cannot be blank")
    @Size(min = 3, max = 20, message = "username must be between 3 and 20 characters")
    private String username;

    @NotNull(message = "password cannot be null")
    @NotBlank(message = "password cannot be blank")
    @Size(min = 8, max = 40, message = "password must be between 8 and 40 characters")
    private String password;

    public LoginRequest() {}

    public LoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
