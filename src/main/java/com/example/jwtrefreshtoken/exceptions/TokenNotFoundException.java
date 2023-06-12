package com.example.jwtrefreshtoken.exceptions;

import org.springframework.security.core.AuthenticationException;

public class TokenNotFoundException extends AuthenticationException{
    public TokenNotFoundException(String token) {
        super("Token is not found: " + token);
    }
}
