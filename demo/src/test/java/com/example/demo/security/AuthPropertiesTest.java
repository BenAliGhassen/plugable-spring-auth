package com.example.demo.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AuthPropertiesTest {

    // Builds a valid AuthProperties where only the two lifetimes vary
    private AuthProperties props(Duration accessTtl, Duration refreshTtl) {
        return new AuthProperties(
                new AuthProperties.Jwt("dGVzdC1zZWNyZXQ="),
                new AuthProperties.Access(accessTtl),
                new AuthProperties.Refresh(Duration.ofDays(3), refreshTtl),
                new AuthProperties.Cookie(true),
                new AuthProperties.Cors(List.of("http://localhost:5173")),
                new AuthProperties.Login(5, 20, Duration.ofMinutes(15)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"PT0S", "-PT1M"})
    void accessTtlMustBePositive(String value) {
        Duration ttl = Duration.parse(value);
        assertThatThrownBy(() -> new AuthProperties.Access(ttl))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("AUTH_ACCESS_TTL");
    }

    @Test
    void accessTtlAcceptsOneSecond() {
        assertThatCode(() -> new AuthProperties.Access(Duration.ofSeconds(1)))
                .doesNotThrowAnyException();
    }

    @Test
    void corsRejectsWildcard() {
        assertThatThrownBy(() -> new AuthProperties.Cors(List.of("*")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void corsRejectsEmptyList() {
        assertThatThrownBy(() -> new AuthProperties.Cors(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void loginRejectsZeroMaxFailure() {
        assertThatThrownBy(() -> new AuthProperties.Login(0, 20, Duration.ofMinutes(15)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("must be greater than zero");
    }

    @Test
    void refreshMustBeLongerThanAccess() {
        assertThatThrownBy(() -> props(Duration.ofMinutes(15), Duration.ofMinutes(15)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be greater than");
    }

    @Test
    void jwtSecretIsMaskedInToString() {
        var jwt = new AuthProperties.Jwt("super-secret-value");
        assertThat(jwt.toString()).doesNotContain("super-secret-value");
    }

    @Test 
    void corsWrongOriginFormat(){
        assertThatThrownBy(()-> new AuthProperties.Cors(List.of("http://LOCALHOST:5173"))).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("AUTH_CORS_ORIGINS is invalid origin");
    }

    @Test 
    void corsOriginIsSpaces(){
        assertThatThrownBy(() -> new AuthProperties.Cors(List.of(" ")) ).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("AUTH_CORS_ORIGINS is invalid origin");
    }
}