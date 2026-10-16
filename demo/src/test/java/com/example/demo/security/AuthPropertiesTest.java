package com.example.demo.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class AuthPropertiesTest {

    private static final String SECRET = "dGVzdC1zZWNyZXQ=";

    // Builds a valid AuthProperties where only the two lifetimes vary
    private AuthProperties props(Duration accessTtl, Duration refreshTtl) {
        return new AuthProperties(
                new AuthProperties.Jwt(SECRET),
                new AuthProperties.Access(accessTtl),
                new AuthProperties.Refresh(Duration.ofDays(3), refreshTtl),
                new AuthProperties.Cookie(true),
                new AuthProperties.Cors(List.of("http://localhost:5173")),
                new AuthProperties.Login(5, 20, Duration.ofMinutes(15)));
    }

    // ---------- Access ----------

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

    // ---------- Refresh ----------

    @Test
    void refreshTtlMustBePositive() {
        assertThatThrownBy(() -> new AuthProperties.Refresh(Duration.ofDays(3), Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("AUTH_REFRESH_TTL value must be filled");
    }

    @Test
    void refreshRetentionMustBePositive() {
        assertThatThrownBy(() -> new AuthProperties.Refresh(Duration.ZERO, Duration.ofDays(7)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("AUTH_REFRESH_RETENTION");
    }

    // ---------- Refresh vs Access (outer check) ----------

    @ParameterizedTest
    @ValueSource(strings = {"PT15M", "PT14M"})   // equal to access, then shorter
    void refreshMustBeLongerThanAccess(String refreshTtl) {
        assertThatThrownBy(() -> props(Duration.ofMinutes(15), Duration.parse(refreshTtl)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("greater than AUTH_ACCESS_TTL");
    }

    @Test
    void refreshJustLongerThanAccessIsAccepted() {
        assertThatCode(() -> props(Duration.ofMinutes(15), Duration.ofMinutes(16)))
                .doesNotThrowAnyException();
    }

    // ---------- Jwt ----------

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void jwtSecretIsRequired(String secret) {
        assertThatThrownBy(() -> new AuthProperties.Jwt(secret))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("AUTH_JWT_SECRET is required");
    }

    @Test
    void jwtSecretIsMaskedInToString() {
        var jwt = new AuthProperties.Jwt("super-secret-value");
        assertThat(jwt.toString()).doesNotContain("super-secret-value");
    }

    @Test
    void jwtSecretIsMaskedWhenWholeConfigIsPrinted() {
        AuthProperties properties = props(Duration.ofMinutes(15), Duration.ofDays(7));
        assertThat(properties.toString()).doesNotContain(SECRET);
    }

    // ---------- Cors ----------

    @ParameterizedTest
    @ValueSource(strings = {
            "http://localhost:5173",
            "https://app.example.com",
            "http://127.0.0.1:8080"
    })
    void corsAcceptsValidOrigin(String origin) {
        assertThatCode(() -> new AuthProperties.Cors(List.of(origin)))
                .doesNotThrowAnyException();
    }

    @Test
    void corsAcceptsSeveralValidOrigins() {
        assertThatCode(() -> new AuthProperties.Cors(
                List.of("http://localhost:5173", "https://app.example.com")))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",                          // empty
            " ",                         // blank
            "*",                         // wildcard
            "localhost:5173",            // missing scheme
            "ftp://example.com",         // wrong scheme
            "HTTP://LOCALHOST:5173",     // uppercase (browsers send lowercase)
            "http://localhost:5173/",    // trailing slash
            "http://localhost:5173/app", // path
            "http://user@example.com",   // user info
            "http://example.com?x=1",    // query
            "http://localhost:5173 "     // trailing space
    })
    void corsRejectsInvalidOrigin(String origin) {
        assertThatThrownBy(() -> new AuthProperties.Cors(List.of(origin)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid origin");
    }

    @Test
    void corsRejectsInvalidOriginEvenAfterValidOne() {
        assertThatThrownBy(() -> new AuthProperties.Cors(
                List.of("http://localhost:5173", "http://localhost:5173/")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid origin");
    }

    @Test
    void corsRejectsNullOrigin() {
        // List.of(...) refuses null elements, so build the list another way
        assertThatThrownBy(() -> new AuthProperties.Cors(Arrays.asList((String) null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid origin");
    }

    @Test
    void corsRejectsEmptyList() {
        assertThatThrownBy(() -> new AuthProperties.Cors(List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("is required");
    }

    @Test
    void corsRejectsNullList() {
        assertThatThrownBy(() -> new AuthProperties.Cors(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("is required");
    }

    // ---------- Login ----------

    @Test
    void loginRejectsZeroMaxFailure() {
        assertThatThrownBy(() -> new AuthProperties.Login(0, 20, Duration.ofMinutes(15)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("AUTH_LOGIN_MAXFAILURE must be greater than zero");
    }

    @Test
    void loginRejectsZeroMaxIpFailure() {
        assertThatThrownBy(() -> new AuthProperties.Login(1, 0, Duration.ofMinutes(15)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("AUTH_LOGIN_MAXIPFAILURE must be greater than zero");
    }

    @Test
    void loginRejectsIpLimitEqualToPairLimit() {
        assertThatThrownBy(() -> new AuthProperties.Login(5, 5, Duration.ofMinutes(15)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("should be greater than AUTH_LOGIN_MAXFAILURE");
    }

    @Test
    void loginAcceptsIpLimitJustAbovePairLimit() {
        assertThatCode(() -> new AuthProperties.Login(5, 6, Duration.ofMinutes(15)))
                .doesNotThrowAnyException();
    }

    @Test
    void loginWindowMustBePositive() {
        assertThatThrownBy(() -> new AuthProperties.Login(5, 20, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("AUTH_LOGIN_WINDOW");
    }
}