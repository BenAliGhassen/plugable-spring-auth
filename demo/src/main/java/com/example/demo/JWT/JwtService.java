package com.example.demo.JWT;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.example.demo.User.User;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private static final long ACCESS_TOKEN_EXPIRATION_MINUTES = 15;

    private final SecretKey signingKey;

    public JwtService(@Value("${jwt.secret}") String base64Secret) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Secret));
    }

    public String generateToken(User user) {
        if (user == null || user.getEmail() == null || user.getEmail().isBlank()) {
            throw new IllegalArgumentException("User email is required to generate a JWT");
        }

        return generateToken(user.getEmail());
    }

    public String generateToken(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("User email is required to generate a JWT");
        }

        Instant issuedAt = Instant.now();
        return Jwts.builder()
                .subject(email)
                .issuedAt(java.util.Date.from(issuedAt))
                .expiration(java.util.Date.from(issuedAt.plus(ACCESS_TOKEN_EXPIRATION_MINUTES, ChronoUnit.MINUTES)))
                .signWith(signingKey)
                .compact();
    }

    public String extractToken(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }
}
