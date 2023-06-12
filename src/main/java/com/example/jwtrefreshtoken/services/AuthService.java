package com.example.jwtrefreshtoken.services;

import java.util.HashSet;
import java.util.Set;

import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import com.example.jwtrefreshtoken.exceptions.RoleNotFoundException;
import com.example.jwtrefreshtoken.exceptions.TokenNotFoundException;
import com.example.jwtrefreshtoken.exceptions.TokenRevokedException;
import com.example.jwtrefreshtoken.models.Role;
import com.example.jwtrefreshtoken.models.RoleType;
import com.example.jwtrefreshtoken.models.Token;
import com.example.jwtrefreshtoken.models.TokenType;
import com.example.jwtrefreshtoken.models.User;
import com.example.jwtrefreshtoken.models.UserDetailsImpl;
import com.example.jwtrefreshtoken.models.UserStatus;
import com.example.jwtrefreshtoken.payloads.mail.EmailDetails;
import com.example.jwtrefreshtoken.payloads.responses.JwtResponse;
import com.example.jwtrefreshtoken.payloads.responses.MessageResponse;
import com.example.jwtrefreshtoken.repositories.RoleRepository;
import com.example.jwtrefreshtoken.repositories.TokenRepository;
import com.example.jwtrefreshtoken.repositories.UserRepository;

@Service
@Transactional
public class AuthService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private EmailService emailService;

    @Value("${application.backend.url}")
    private String backend_url;

    public ResponseEntity<?> registerUser(String username, String email, String password, Set<String> strRoles) {
        if (userRepository.existsByUsername(username)) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken"));
        }
        if (userRepository.existsByEmail(email)) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already taken"));
        }
        User user = User.builder().username(username).email(email).password(passwordEncoder.encode(password)).build();
        Set<Role> roles = new HashSet<>();
        if (strRoles.isEmpty()) {
            Role userRole = roleRepository.findByName(RoleType.ROLE_USER).orElseThrow(() -> new RoleNotFoundException(RoleType.ROLE_USER.name()));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(RoleType.ROLE_ADMIN).orElseThrow(() -> 
                            new RoleNotFoundException(RoleType.ROLE_ADMIN.name()));
                        roles.add(adminRole);
                        break;
                    case "moderator":
                        Role moderatorRole = roleRepository.findByName(RoleType.ROLE_MODERATOR).orElseThrow(() -> 
                            new RoleNotFoundException(RoleType.ROLE_MODERATOR.name()));
                        roles.add(moderatorRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(RoleType.ROLE_USER).orElseThrow(() -> 
                            new RoleNotFoundException(RoleType.ROLE_USER.name()));
                        roles.add(userRole);
                        break;
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);

        String verificationToken = jwtService.generateEmailVerificationToken(user);
        saveUserToken(user, verificationToken, TokenType.EMAIL_VERIFICATION_TOKEN);

        EmailDetails emailDetails = EmailDetails.builder()
            .recipient(user.getEmail())
            .msgBody("To confirm your account, please click here : "
            + backend_url + "/api/v1/auth/confirm-account?token=" + verificationToken)
            .subject("Verify your Sportify account here")
            .build();
        emailService.sendSimpleMail(emailDetails);
        return ResponseEntity.ok( new MessageResponse("Your account has been created. Check your mail to verify it."));
    }

    public ResponseEntity<?> authenticateUser (String username, String password) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Error: Username is not found"));
        if (user.getUserStatus() == UserStatus.UNVERIFIED) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Please verify your account first"));
        }
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        revokeAllUserTokens(user);
        String jwtAccessToken = jwtService.generateJwtAccessToken(username);
        String jwtRefreshToken = jwtService.generateJwtRefreshToken(username);
        saveUserToken(user, jwtAccessToken, TokenType.ACCESS_TOKEN);
        saveUserToken(user, jwtRefreshToken, TokenType.REFRESH_TOKEN);
        return ResponseEntity.ok(JwtResponse.builder()
                .userStatus(user.getUserStatus().name())
                .accessToken(jwtAccessToken)
                .refreshToken(jwtRefreshToken)
                .build());
    }

    public ResponseEntity<?> refreshToken(String refreshToken) {
        String jwt = jwtService.parseJwt(refreshToken);
        if (StringUtils.hasText(jwt)) {
            Token token = tokenRepository.findToken(jwt, TokenType.REFRESH_TOKEN).orElseThrow(() -> new TokenNotFoundException("Error: JWT Refresh Token is not found"));
            if (token.getIsRevoked()) {
                revokeAllUserTokens(token.getUser());
                SecurityContextHolder.getContext().setAuthentication(null);
                throw new TokenRevokedException("Error: JWT Refresh Token is revoked. Please Authenticate yourself again.");
            }
            if (jwtService.validateJwtRefreshToken(jwt)) {
                String username = jwtService.getUsernameFromJwtRefreshToken(jwt);
                User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Error: Username is not found"));
                revokeAllUserTokens(user);
                String jwtAccessToken = jwtService.generateJwtAccessToken(username);
                String jwtRefreshToken = jwtService.generateJwtRefreshToken(username);
                saveUserToken(user, jwtAccessToken, TokenType.ACCESS_TOKEN);
                saveUserToken(user, jwtRefreshToken, TokenType.REFRESH_TOKEN);

                return ResponseEntity.ok(JwtResponse.builder()
                        .userStatus(user.getUserStatus().name())
                        .accessToken(jwtAccessToken)
                        .refreshToken(jwtRefreshToken)
                        .build());
            }
        }
        return ResponseEntity.badRequest().body(new MessageResponse("Error: Refresh Token is not valid"));
    }

    public ResponseEntity<?> logoutUser() {
        UserDetailsImpl userDetailsImpl = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        User user = userRepository.findByUsername(userDetailsImpl.getUsername()).orElseThrow(() -> new UsernameNotFoundException("Error: Username is not found"));
        revokeAllUserTokens(user);
        SecurityContextHolder.getContext().setAuthentication(null);
        return ResponseEntity.ok( new MessageResponse("Successfully logout"));
    }

    public void revokeAllUserTokens(User user) {
        var tokens = tokenRepository.findAllAvailableTokensByUser(user.getId());
        if (tokens.isEmpty()) {
            return;
        }
        tokens.forEach(token -> {
            token.setIsRevoked(true);
        });
        tokenRepository.saveAll(tokens);
    }

    private void saveUserToken(User user, String token, TokenType tokenType) {
        tokenRepository.save(Token.builder()
            .user(user)
            .token(token)
            .tokenType(tokenType)
            .isRevoked(false)
            .build()
        );
    }

    public ResponseEntity<?> confirmAccount(String confirmToken) {
        Token verificationToken = tokenRepository.findToken(confirmToken, TokenType.EMAIL_VERIFICATION_TOKEN).orElseThrow(() -> new TokenNotFoundException("Error: Verfication Token is not found"));
        if (verificationToken.getIsRevoked()) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Verification Token is not valid"));
        }
        User user = verificationToken.getUser();
        revokeAllUserTokens(user);
        user.setUserStatus(UserStatus.VERIFIED);
        userRepository.save(user);
        return ResponseEntity.ok( new MessageResponse("Your account has been verified"));
    }
}
