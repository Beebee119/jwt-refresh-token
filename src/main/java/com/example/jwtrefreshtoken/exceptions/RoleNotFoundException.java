package com.example.jwtrefreshtoken.exceptions;

public class RoleNotFoundException extends RuntimeException {
    public RoleNotFoundException(String role) {
        super("Role is not found: " + role);
    }
}
