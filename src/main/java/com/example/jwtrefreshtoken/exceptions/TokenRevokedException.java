package com.example.jwtrefreshtoken.exceptions;

import org.springframework.security.core.AuthenticationException;

public class TokenRevokedException extends AuthenticationException{
    public TokenRevokedException(String message) {
        super(message);
    }
}
