package com.example.jwtrefreshtoken.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.example.jwtrefreshtoken.payloads.requests.LoginRequest;
import com.example.jwtrefreshtoken.payloads.requests.RefreshRequest;
import com.example.jwtrefreshtoken.payloads.requests.RegisterRequest;
import com.example.jwtrefreshtoken.services.AuthService;
import jakarta.validation.Valid;

@RestController
@CrossOrigin(origins = "*", maxAge = 3600)
@RequestMapping("/api/v1/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        return authService.registerUser(
            registerRequest.getUsername(), 
            registerRequest.getEmail(), 
            registerRequest.getPassword(),
            registerRequest.getRoles()
        );
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        return authService.authenticateUser(loginRequest.getUsername(), loginRequest.getPassword());
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshRequest refreshRequest) {
        return authService.refreshToken(refreshRequest.getRefreshToken());
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser() {
        return authService.logoutUser();
    }

    @GetMapping("/confirm-account")
    public ResponseEntity<?> confirmAccount(@RequestParam("token") String confirmationToken) {
        return authService.confirmAccount(confirmationToken);
    }
}
