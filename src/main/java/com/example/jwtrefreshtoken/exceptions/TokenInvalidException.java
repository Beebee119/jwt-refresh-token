package com.example.jwtrefreshtoken.exceptions;

import org.springframework.security.core.AuthenticationException;

public class TokenInvalidException extends AuthenticationException {
    public TokenInvalidException(String message) {
        super(message);
    }
}