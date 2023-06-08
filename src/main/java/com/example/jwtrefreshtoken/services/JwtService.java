package com.example.jwtrefreshtoken.services;

import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.example.jwtrefreshtoken.exceptions.TokenRevokedException;
import com.example.jwtrefreshtoken.models.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    @Value("${application.security.jwt.access-token-secret}")
    private String jwtAccessTokenSecret;

    @Value("${application.security.jwt.refresh-token-secret}")
    private String jwtRefreshTokenSecret;

    @Value("${application.security.jwt.access-token.expirationMs}")
    private Long jwtAccessTokenExpiration;

    @Value("${application.security.jwt.refresh-token.expirationMs}")
    private Long jwtRefreshTokenExpiration;

    private Key key(String secret) {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    public String generateJwtAccessToken(String username) {
        return  Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + jwtAccessTokenExpiration))
                    .signWith(key(jwtAccessTokenSecret), SignatureAlgorithm.HS256)
                    .compact();
    }

    public String generateJwtRefreshToken(String username) {
        return  Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + jwtRefreshTokenExpiration))
                    .signWith(key(jwtRefreshTokenSecret), SignatureAlgorithm.HS256)
                    .compact();
    }

    public String getUsernameFromJwtAccessToken(String token) {
        return Jwts.parserBuilder()
                    .setSigningKey(key(jwtAccessTokenSecret))
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
    }

    public String getUsernameFromJwtRefreshToken(String token) {
        return Jwts.parserBuilder()
                    .setSigningKey(key(jwtRefreshTokenSecret))
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
    }

    public boolean validateJwtAccessToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key(jwtAccessTokenSecret))
                    .build()
                    .parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT Access Token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT Access Token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT Access Token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT Access Token claims string is empty: {}", e.getMessage());
        }
        return false;
    }
    
    public boolean validateJwtRefreshToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key(jwtRefreshTokenSecret))
                    .build()
                    .parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT Refresh Token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT Refresh Token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT Refresh Token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT Refresh Token claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    public String parseJwt(String token) {
        if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            return token.split(" ")[1].trim();
        }
        return null;
    }
}
