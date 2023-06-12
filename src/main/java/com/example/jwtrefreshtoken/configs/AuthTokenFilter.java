package com.example.jwtrefreshtoken.configs;

import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.jwtrefreshtoken.exceptions.TokenNotFoundException;
import com.example.jwtrefreshtoken.exceptions.TokenRevokedException;
import com.example.jwtrefreshtoken.models.Token;
import com.example.jwtrefreshtoken.models.TokenType;
import com.example.jwtrefreshtoken.repositories.TokenRepository;
import com.example.jwtrefreshtoken.repositories.UserRepository;
import com.example.jwtrefreshtoken.services.AuthService;
import com.example.jwtrefreshtoken.services.JwtService;
import com.example.jwtrefreshtoken.services.UserDetailsServiceImpl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthService authService;

    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;

    @Autowired
    private TokenRepository tokenRepository;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = jwtService.parseJwt(request.getHeader("Authorization"));
            if (StringUtils.hasText(jwt)) {
                Token token = tokenRepository.findToken(jwt, TokenType.ACCESS_TOKEN).orElseThrow(() -> new TokenNotFoundException("Error: JWT Token is not found"));
                if (token.getIsRevoked()) {
                    authService.revokeAllUserTokens(token.getUser());
                    SecurityContextHolder.getContext().setAuthentication(null);
                    throw new TokenRevokedException("Error: JWT is revoked. Please Authenticate yourself again.");
                }
                if (jwtService.validateJwtAccessToken(jwt)){
                    String username = jwtService.getUsernameFromJwtAccessToken(jwt);
                    UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(username);
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }
        filterChain.doFilter(request, response);
    }
}
