package com.example.demo.security.jwt;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;
import com.example.demo.security.AuthProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private final AuthProperties authProps;
    private final SecretKey siginingKey;

    public JwtService(AuthProperties authProps) {
        this.authProps = authProps;
        this.siginingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(authProps.jwt().secret()));
    }



    public String generateToken(String username, Collection<String> roles) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username is required to generate a JWT");
        }


        Instant issuedAt = Instant.now();
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(java.util.Date.from(issuedAt))
                .expiration(java.util.Date.from(issuedAt.plus(authProps.access().ttl())))
                .signWith(siginingKey)
                .compact();
    }

    public TokenClaims parseToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(siginingKey)
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
