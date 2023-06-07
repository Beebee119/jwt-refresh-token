package com.example.jwtrefreshtoken.scripts;

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.jwtrefreshtoken.models.ERole;
import com.example.jwtrefreshtoken.models.Role;
import com.example.jwtrefreshtoken.models.User;
import com.example.jwtrefreshtoken.repositories.RoleRepository;
import com.example.jwtrefreshtoken.repositories.UserRepository;

@Configuration
public class SeedDatabase {
    private static final Logger logger = LoggerFactory.getLogger(SeedDatabase.class);

    @Bean
    CommandLineRunner commandLineRunner(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if(roleRepository.findByName(ERole.ROLE_ADMIN).isPresent()) {
                return;
            }
            Role adminRole = roleRepository.save(new Role(ERole.ROLE_ADMIN));
            Role moderatorRole = roleRepository.save(new Role(ERole.ROLE_MODERATOR));
            Role userRole = roleRepository.save(new Role(ERole.ROLE_USER));
            logger.info("Perloading " + adminRole);
            logger.info("Perloading " + moderatorRole);
            logger.info("Perloading " + userRole);
            
            Set<Role> adminRoles = new HashSet<>();
            Set<Role> moderatorRoles = new HashSet<>();
            adminRoles.add(adminRole);
            moderatorRoles.add(moderatorRole);

            logger.info("Perloading " + userRepository.save(new User(
                "admin 1", "admin1.email@test.com", passwordEncoder.encode("password"), adminRoles))
            );

            logger.info("Perloading " + userRepository.save(new User(
                "moderator 1", "moderator1.email@test.com", passwordEncoder.encode("password"), moderatorRoles))
            );
        };
    }
}
