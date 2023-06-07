package com.example.jwtrefreshtoken.controllers;

import java.util.HashSet;
import java.util.Set;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.jwtrefreshtoken.models.ERole;
import com.example.jwtrefreshtoken.models.Role;
import com.example.jwtrefreshtoken.models.User;
import com.example.jwtrefreshtoken.payloads.requests.LoginRequest;
import com.example.jwtrefreshtoken.payloads.requests.RegisterRequest;
import com.example.jwtrefreshtoken.payloads.responses.JwtResponse;
import com.example.jwtrefreshtoken.payloads.responses.MessageResponse;
import com.example.jwtrefreshtoken.repositories.RoleRepository;
import com.example.jwtrefreshtoken.repositories.UserRepository;
import com.example.jwtrefreshtoken.services.JwtService;

@RestController
@CrossOrigin(origins = "*", maxAge = 3600)
@RequestMapping("/api/v1/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken"));
        }
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already taken"));
        }

        User user = new User(
            registerRequest.getUsername(), registerRequest.getEmail(), passwordEncoder.encode(registerRequest.getPassword())
        );
        Set<String> strRoles = registerRequest.getRoles();
        Set<Role> roles = new HashSet<>();
        if (strRoles.isEmpty()) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: Role is not found"));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN).orElseThrow(() -> 
                            new RuntimeException("Error: Role Admin is not found"));
                        roles.add(adminRole);
                        break;
                    case "moderator":
                        Role moderatorRole = roleRepository.findByName(ERole.ROLE_MODERATOR).orElseThrow(() -> 
                            new RuntimeException("Error: Role Moderator is not found"));
                        roles.add(moderatorRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> 
                            new RuntimeException("Error: Role is not found"));
                        roles.add(userRole);
                        break;
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return authenticateUser(registerRequest.getUsername(), registerRequest.getPassword());
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        return authenticateUser(loginRequest.getUsername(), loginRequest.getPassword());
    }

    public ResponseEntity<?> authenticateUser(String username, String password) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwtAccessToken = jwtService.generateJwtAccessToken(authentication);
        String jwtRefreshToken = jwtService.generateJwtRefreshToken(authentication);

        // UserDetailsImpl userDetailsImpl = (UserDetailsImpl) authentication.getPrincipal();
        // List<String> roles = userDetailsImpl.getAuthorities().stream().map(item -> 
        //     item.getAuthority()).collect(Collectors.toList());
        return ResponseEntity.ok(new JwtResponse(jwtAccessToken, jwtRefreshToken));
    }
}
