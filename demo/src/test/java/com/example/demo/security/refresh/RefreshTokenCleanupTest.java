package com.example.demo.security.refresh;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.example.demo.security.AuthProperties;

@ExtendWith(MockitoExtension.class)
class RefreshTokenCleanupTest {

    private static final Instant T = Instant.parse("2020-01-01T00:00:00Z");

    @Mock
    private RefreshRepository refreshRepository;

    private RefreshTokenCleanup cleanup;

    @BeforeEach
    void setUp() {
        AuthProperties properties = new AuthProperties(
                new AuthProperties.Jwt("test-secret"),
                new AuthProperties.Access(Duration.ofMinutes(15)),
                new AuthProperties.Refresh(Duration.ofDays(3), Duration.ofDays(7)),
                new AuthProperties.Cookie(true),
                new AuthProperties.Cors(List.of("http://localhost:5173")),
                new AuthProperties.Login(5, 20, Duration.ofMinutes(15)));

        cleanup = new RefreshTokenCleanup(
                refreshRepository,
                properties,
                Clock.fixed(T, ZoneOffset.UTC));
    }

    @Test
    void cleanupTokenDeletesTokensOlderThanRetentionCutoffExactlyOnce() {
        Instant expectedCutoff = T.minus(Duration.ofDays(3));

        cleanup.cleanupToken();

        verify(refreshRepository, times(1)).deleteToken(expectedCutoff);
    }

    @Test
    void cleanupTokenDoesNotThrowWhenNoTokensAreDeleted() {
        when(refreshRepository.deleteToken(T.minus(Duration.ofDays(3)))).thenReturn(0);

        assertThatCode(() -> cleanup.cleanupToken()).doesNotThrowAnyException();
    }
}
