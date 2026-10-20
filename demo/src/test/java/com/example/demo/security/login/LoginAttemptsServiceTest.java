package com.example.demo.security.login;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.example.demo.security.AuthProperties;
import com.github.benmanes.caffeine.cache.Ticker;

class LoginAttemptsServiceTest {

    private static final String IP = "192.0.2.10";
    private static final String USERNAME = "ali@example.com";

    private ManualTicker ticker;
    private LoginAttemptsService service;

    @BeforeEach
    void setUp() {
        ticker = new ManualTicker();
        service = new LoginAttemptsService(authProperties(), ticker);
    }

    @Test
    void pairIsNotBlockedAfterFourFailures() {
        for (int failure = 0; failure < 4; failure++) {
            service.recordFailure(IP, USERNAME);
        }

        assertThat(service.isBlocked(IP, USERNAME)).isFalse();
    }

    @Test
    void pairIsBlockedAfterFiveFailures() {
        for (int failure = 0; failure < 5; failure++) {
            service.recordFailure(IP, USERNAME);
        }

        assertThat(service.isBlocked(IP, USERNAME)).isTrue();
    }

    @Test
    void ipIsNotBlockedAfterNineteenFailuresAcrossDifferentUsernames() {
        recordFailuresForDifferentUsernames(19);

        assertThat(service.isBlocked(IP, "another@example.com")).isFalse();
    }

    @Test
    void ipBlocksAnyUsernameAfterTwentyFailuresAcrossDifferentUsernames() {
        recordFailuresForDifferentUsernames(20);

        assertThat(service.isBlocked(IP, "another@example.com")).isTrue();
    }

    @Test
    void failuresForUsernameOnDifferentIpDoNotBlockThePair() {
        for (int failure = 0; failure < 5; failure++) {
            service.recordFailure(IP, USERNAME);
        }

        assertThat(service.isBlocked("192.0.2.11", USERNAME)).isFalse();
    }

    @Test
    void usernameIsNormalizedByTrimmingAndLowercasing() {
        for (int failure = 0; failure < 4; failure++) {
            service.recordFailure(IP, "Ali@X.com ");
        }
        assertThat(service.isBlocked(IP, "ali@x.com")).isFalse();

        service.recordFailure(IP, "ali@x.com");

        assertThat(service.isBlocked(IP, "Ali@X.com ")).isTrue();
    }

    @Test
    void successClearsPairCounterButPreservesIpCounter() {
        for (int failure = 0; failure < 5; failure++) {
            service.recordFailure(IP, USERNAME);
        }
        assertThat(service.isBlocked(IP, USERNAME)).isTrue();

        service.recordSuccess(IP, USERNAME);
        assertThat(service.isBlocked(IP, USERNAME)).isFalse();

        recordFailuresForDifferentUsernames(15);

        assertThat(service.isBlocked(IP, "another@example.com")).isTrue();
    }

    @Test
    void pairRemainsBlockedJustBeforeWindowAfterLastFailure() {
        recordPairFailures(4);
        ticker.advance(Duration.ofMinutes(14));
        service.recordFailure(IP, USERNAME);
        ticker.advance(Duration.ofMinutes(15).minusNanos(1));

        assertThat(service.isBlocked(IP, USERNAME)).isTrue();
    }

    @Test
    void pairIsUnblockedAtWindowAfterLastFailure() {
        recordPairFailures(4);
        ticker.advance(Duration.ofMinutes(14));
        service.recordFailure(IP, USERNAME);
        ticker.advance(Duration.ofMinutes(15));

        assertThat(service.isBlocked(IP, USERNAME)).isFalse();
    }

    @Test
    void pairIsUnblockedAfterWindowAfterLastFailure() {
        recordPairFailures(4);
        ticker.advance(Duration.ofMinutes(14));
        service.recordFailure(IP, USERNAME);
        ticker.advance(Duration.ofMinutes(15).plusNanos(1));

        assertThat(service.isBlocked(IP, USERNAME)).isFalse();
    }

    @Test
    void blockedChecksDoNotExtendTheBlock() {
        recordPairFailures(5);
        ticker.advance(Duration.ofMinutes(14));
        assertThat(service.isBlocked(IP, USERNAME)).isTrue();

        ticker.advance(Duration.ofMinutes(1));

        assertThat(service.isBlocked(IP, USERNAME)).isFalse();
    }

    @Test
    void ipBlockedChecksDoNotExtendTheBlock() {
        recordFailuresForDifferentUsernames(20);
        ticker.advance(Duration.ofMinutes(14));
        assertThat(service.isBlocked(IP, "user@example.com")).isTrue();

        ticker.advance(Duration.ofMinutes(1));

        assertThat(service.isBlocked(IP, "user@example.com")).isFalse();
    }

    private void recordPairFailures(int count) {
        for (int failure = 0; failure < count; failure++) {
            service.recordFailure(IP, USERNAME);
        }
    }

    private void recordFailuresForDifferentUsernames(int count) {
        for (int failure = 0; failure < count; failure++) {
            service.recordFailure(IP, "user-" + failure + "@example.com");
        }
    }

    private static AuthProperties authProperties() {
        return new AuthProperties(
                new AuthProperties.Jwt("dGVzdC1zZWNyZXQ="),
                new AuthProperties.Access(Duration.ofMinutes(15)),
                new AuthProperties.Refresh(Duration.ofDays(3), Duration.ofDays(7)),
                new AuthProperties.Cookie(true),
                new AuthProperties.Cors(List.of("http://localhost:5173")),
                new AuthProperties.Login(5, 20, Duration.ofMinutes(15)));
    }

    private static final class ManualTicker implements Ticker {
        private final AtomicLong nanos = new AtomicLong();

        @Override
        public long read() {
            return nanos.get();
        }

        private void advance(Duration duration) {
            nanos.addAndGet(duration.toNanos());
        }
    }
}
