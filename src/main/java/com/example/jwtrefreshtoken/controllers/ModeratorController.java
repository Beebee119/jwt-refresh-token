package com.example.jwtrefreshtoken.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/v1/moderators")
public class ModeratorController {
    @GetMapping("/hello")
    @PreAuthorize("hasRole('MODERATOR') or hasRole('ADMIN')")
    public String helloModerator() {
        return "Hello, Moderator";
    }
}