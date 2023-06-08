package com.example.jwtrefreshtoken.repositories;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.example.jwtrefreshtoken.models.Token;
import com.example.jwtrefreshtoken.models.TokenType;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    @Query("""
        SELECT t FROM Token t WHERE t.token = :token AND t.tokenType = :tokenType
            """)
    Optional<Token> findToken(String token, TokenType tokenType);

    @Query("""
            SELECT t FROM Token t INNER JOIN User u on t.user.id = u.id WHERE u.id = :userId and t.isRevoked = false
            """)
    Set<Token> findAllAvailableTokensByUser(Long userId);
}
