package com.example.jwtrefreshtoken.payloads.requests;

import java.util.HashSet;
import java.util.Set;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;


public class RegisterRequest {
    
    @NotNull(message = "username cannot be null")
    @NotBlank(message = "username cannot be blank")
    @Size(min = 3, max = 20, message = "username must be between 3 and 20 characters")
    private String username;
    
    @Pattern(regexp = "^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@" 
        + "[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$", message = "email is not valid")
    @NotNull(message = "email cannot be null")
    @NotBlank(message = "email cannot be blank")
    @Size(max = 50, message = "email cannot be more than 50 characters")
    private String email;

    @NotNull(message = "password cannot be null")
    @NotBlank(message = "password cannot be blank")
    @Size(min = 8, max = 40, message = "password must be between 8 and 40 characters")
    private String password;

    private Set<String> roles = new HashSet<>();

    public RegisterRequest() {}

    public RegisterRequest(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }
    
    public RegisterRequest(String username, String email, String password, Set<String> roles) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.roles = roles;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
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

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }
}
