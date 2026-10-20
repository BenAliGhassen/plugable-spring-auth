package com.example.demo.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.example.demo.security.AuthProperties;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.WeakKeyException;

class JwtServiceTest {

    private static final Instant T = Instant.parse("2020-01-01T00:00:00Z");
    private static final String SECRET = Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8));
    private static final String DIFFERENT_SECRET = Base64.getEncoder().encodeToString("abcdef0123456789abcdef0123456789".getBytes(StandardCharsets.UTF_8));

    private AuthProperties authProperties;
    private JwtService serviceAtT;

    @BeforeEach
    void setUp() {
        authProperties = authProperties(SECRET);
        serviceAtT = serviceAt(T, authProperties);
    }

    @Test
    void parseTokenReturnsUsernameAndRolesUsedToGenerateToken() {
        List<String> roles = List.of("USER", "ADMIN");

        String token = serviceAtT.generateToken("alice@example.com", roles);
        TokenClaims claims = serviceAtT.parseToken(token);

        assertThat(claims.username()).isEqualTo("alice@example.com");
        assertThat(claims.roles()).isEqualTo(List.of("USER", "ADMIN"));
    }

    @Test
    void generateTokenRejectsNullUsername() {
        assertThatThrownBy(() -> serviceAtT.generateToken(null, List.of("USER")))
                .isExactlyInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void generateTokenRejectsEmptyUsername() {
        assertThatThrownBy(() -> serviceAtT.generateToken("", List.of("USER")))
                .isExactlyInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void generateTokenRejectsBlankUsername() {
        assertThatThrownBy(() -> serviceAtT.generateToken(" \t ", List.of("USER")))
                .isExactlyInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void parseTokenAcceptsTokenOneSecondBeforeExpiry() {
        String token = serviceAtT.generateToken("alice@example.com", List.of("USER"));
        JwtService serviceBeforeExpiry = serviceAt(T.plus(Duration.ofMinutes(15)).minusSeconds(1), authProperties);

        TokenClaims claims = serviceBeforeExpiry.parseToken(token);

        assertThat(claims.username()).isEqualTo("alice@example.com");
        assertThat(claims.roles()).isEqualTo(List.of("USER"));
    }

    @Test
    void parseTokenAcceptsTokenAtExpiryTime() {
        String token = serviceAtT.generateToken("alice@example.com", List.of("USER"));
        JwtService serviceAtExpiry = serviceAt(T.plus(Duration.ofMinutes(15)), authProperties);

        // jjwt 0.12.6 expires a token only after exp; equality with the current time is accepted.
        TokenClaims claims = serviceAtExpiry.parseToken(token);

        assertThat(claims.username()).isEqualTo("alice@example.com");
        assertThat(claims.roles()).isEqualTo(List.of("USER"));
    }

    @Test
    void parseTokenRejectsTokenOneSecondAfterExpiry() {
        String token = serviceAtT.generateToken("alice@example.com", List.of("USER"));
        JwtService serviceAfterExpiry = serviceAt(T.plus(Duration.ofMinutes(15)).plusSeconds(1), authProperties);

        assertThatThrownBy(() -> serviceAfterExpiry.parseToken(token))
                .isExactlyInstanceOf(ExpiredJwtException.class);
    }

    @Test
    void parseTokenRejectsModifiedPayload() {
        String token = serviceAtT.generateToken("alice", List.of("USER"));
        String[] parts = token.split("\\.", -1);
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        String modifiedPayload = payload.replace("\"sub\":\"alice\"", "\"sub\":\"other\"");
        String modifiedToken = parts[0] + "."
                + Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(modifiedPayload.getBytes(StandardCharsets.UTF_8))
                + "." + parts[2];

        assertThatThrownBy(() -> serviceAtT.parseToken(modifiedToken))
                .isExactlyInstanceOf(SignatureException.class);
    }

    @Test
    void parseTokenRejectsModifiedSignature() {
        String token = serviceAtT.generateToken("alice", List.of("USER"));
        String[] parts = token.split("\\.", -1);
        byte[] modifiedSignature = Base64.getUrlDecoder().decode(parts[2]);
        modifiedSignature[0] ^= 1;
        String modifiedToken = parts[0] + "." + parts[1] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(modifiedSignature);

        assertThatThrownBy(() -> serviceAtT.parseToken(modifiedToken))
                .isExactlyInstanceOf(SignatureException.class);
    }

    @Test
    void parseTokenRejectsTokenSignedWithDifferentSecret() {
        String token = serviceAtT.generateToken("alice", List.of("USER"));
        JwtService serviceWithDifferentSecret = serviceAt(T, authProperties(DIFFERENT_SECRET));

        assertThatThrownBy(() -> serviceWithDifferentSecret.parseToken(token))
                .isExactlyInstanceOf(SignatureException.class);
    }

    @Test
    void parseTokenRejectsRandomNonJwtString() {
        assertThatThrownBy(() -> serviceAtT.parseToken("not-a-jwt"))
                .isExactlyInstanceOf(MalformedJwtException.class);
    }

    @Test
    void parseTokenRejectsUnsignedToken() {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"alice\",\"iat\":1577836800,\"exp\":1577837700}"
                        .getBytes(StandardCharsets.UTF_8));
        String unsignedToken = header + "." + payload + ".";

        assertThatThrownBy(() -> serviceAtT.parseToken(unsignedToken))
                .isExactlyInstanceOf(UnsupportedJwtException.class);
    }

    @Test
    void parseTokenDropsNonStringRoleEntries() {
        String token = signedToken("alice", List.of("USER", 42, true));

        TokenClaims claims = serviceAtT.parseToken(token);

        assertThat(claims.roles()).isEqualTo(List.of("USER"));
    }

    @Test
    void parseTokenReturnsEmptyRolesWhenRolesClaimIsMissing() {
        String token = signedTokenWithoutRoles("alice");

        TokenClaims claims = serviceAtT.parseToken(token);

        assertThat(claims.roles()).isEqualTo(List.of());
    }

    @Test
    void constructorRejectsSecretShorterThanThirtyTwoBytes() {
        String shortSecret = Base64.getEncoder().encodeToString(
                "0123456789abcdef0123456789abcde".getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> serviceAt(T, authProperties(shortSecret)))
                .isExactlyInstanceOf(WeakKeyException.class);
    }

    private String signedToken(String username, Object roles) {
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(Date.from(T))
                .expiration(Date.from(T.plus(Duration.ofMinutes(15))))
                .signWith(signingKey(SECRET))
                .compact();
    }

    private String signedTokenWithoutRoles(String username) {
        return Jwts.builder()
                .subject(username)
                .issuedAt(Date.from(T))
                .expiration(Date.from(T.plus(Duration.ofMinutes(15))))
                .signWith(signingKey(SECRET))
                .compact();
    }

    private static SecretKey signingKey(String secret) {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    private static JwtService serviceAt(Instant instant, AuthProperties properties) {
        return new JwtService(properties, Clock.fixed(instant, ZoneOffset.UTC));
    }

    private static AuthProperties authProperties(String secret) {
        return new AuthProperties(
                new AuthProperties.Jwt(secret),
                new AuthProperties.Access(Duration.ofMinutes(15)),
                new AuthProperties.Refresh(Duration.ofDays(3), Duration.ofDays(7)),
                new AuthProperties.Cookie(true),
                new AuthProperties.Cors(List.of("http://localhost:5173")),
                new AuthProperties.Login(5, 20, Duration.ofMinutes(15)));
    }
}
