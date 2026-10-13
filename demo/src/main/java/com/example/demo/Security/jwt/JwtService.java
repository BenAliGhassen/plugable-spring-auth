package com.example.demo.security.jwt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private final SecretKey signingKey;
    private final long accessTokenExpirationMinutes;

    public JwtService(@Value("${jwt.secret}") String base64Secret, @Value("${ACCESS_TOKEN_EXPIRATION_MINUTES:15}") long accessTokenExpirationMinutes) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Secret));
        this.accessTokenExpirationMinutes = accessTokenExpirationMinutes;
    }


    public String generateToken(String email, Collection<String> roles) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("User email is required to generate a JWT");
        }

        Instant issuedAt = Instant.now();
        return Jwts.builder()
                .subject(email)
                .claim("roles", roles)
                .issuedAt(java.util.Date.from(issuedAt))
                .expiration(java.util.Date.from(issuedAt.plus(accessTokenExpirationMinutes, ChronoUnit.MINUTES)))
                .signWith(signingKey)
                .compact();
    }

    public TokenClaims parseToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        String username = claims.getSubject();
        List<String> roles = readRoles(claims.get("roles"));   
        return new TokenClaims(username,roles);     

    }

    private List<String> readRoles(Object raw){
        if(raw instanceof List<?> list){
            return list.stream().filter(String.class::isInstance).map(String.class::cast).toList();
        }
        return List.of();
    }
}
