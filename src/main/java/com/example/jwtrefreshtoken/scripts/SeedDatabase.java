package com.example.jwtrefreshtoken.scripts;

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.jwtrefreshtoken.models.RoleType;
import com.example.jwtrefreshtoken.models.Role;
import com.example.jwtrefreshtoken.models.User;
import com.example.jwtrefreshtoken.models.UserStatus;
import com.example.jwtrefreshtoken.repositories.RoleRepository;
import com.example.jwtrefreshtoken.repositories.UserRepository;

@Configuration
public class SeedDatabase {
    private static final Logger logger = LoggerFactory.getLogger(SeedDatabase.class);

    @Bean
    CommandLineRunner commandLineRunner(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if(roleRepository.findByName(RoleType.ROLE_ADMIN).isPresent()) {
                return;
            }
            Role adminRole = roleRepository.save(Role.builder().name(RoleType.ROLE_ADMIN).build());
            Role moderatorRole = roleRepository.save(Role.builder().name(RoleType.ROLE_MODERATOR).build());
            Role userRole = roleRepository.save(Role.builder().name(RoleType.ROLE_USER).build());
            logger.info("Perloading " + adminRole);
            logger.info("Perloading " + moderatorRole);
            logger.info("Perloading " + userRole);
            
            Set<Role> adminRoles = new HashSet<>();
            Set<Role> moderatorRoles = new HashSet<>();
            adminRoles.add(adminRole);
            moderatorRoles.add(moderatorRole);

            logger.info("Perloading " + userRepository.save(User.builder()
                .username("admin 1")
                .email("admin1.email@test.com")
                .password(passwordEncoder.encode("password1"))
                .roles(adminRoles)
                .userStatus(UserStatus.ACTIVE)
                .build())
            );
            
            logger.info("Perloading " + userRepository.save(User.builder()
                .username("moderator 1")
                .email("moderator1.email@test.com")
                .password(passwordEncoder.encode("password1"))
                .roles(moderatorRoles)
                .userStatus(UserStatus.ACTIVE)
                .build())
            );
        };
    }
}
