package com.example.jwtrefreshtoken.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.jwtrefreshtoken.models.User;
import com.example.jwtrefreshtoken.models.UserDetailsImpl;
import com.example.jwtrefreshtoken.repositories.UserRepository;
import jakarta.transaction.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() -> 
            new UsernameNotFoundException("User not found with username: " + username));
        return UserDetailsImpl.build(user);
    }
    
}
