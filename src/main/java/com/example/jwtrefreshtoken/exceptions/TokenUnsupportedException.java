package com.example.jwtrefreshtoken.exceptions;

import org.springframework.security.core.AuthenticationException;

public class TokenUnsupportedException extends AuthenticationException {
    public TokenUnsupportedException(String message) {
        super(message);
    }
}