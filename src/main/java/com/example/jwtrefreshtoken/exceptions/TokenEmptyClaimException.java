package com.example.jwtrefreshtoken.exceptions;

import org.springframework.security.core.AuthenticationException;

public class TokenEmptyClaimException extends AuthenticationException {
    public TokenEmptyClaimException(String message) {
        super(message);
    }
}