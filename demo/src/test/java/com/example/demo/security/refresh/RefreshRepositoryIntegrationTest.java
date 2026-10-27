package com.example.demo.security.refresh;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import jakarta.persistence.EntityManager;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.annotation.Transactional;

import com.example.demo.TestContainerConfiguration;

@SpringBootTest
@Import(TestContainerConfiguration.class)
@Transactional
class RefreshRepositoryIntegrationTest {

    @Autowired
    private RefreshRepository refreshRepository;

    @Autowired
    private EntityManager entityManager;

    private Instant now;

    @BeforeEach
    void setUp() {
        now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    }

    @Test
    void consumeIfActiveRevokesAnActiveTokenAndReturnsOne() {
        RefreshToken token = saveToken("consume-active", false, now.plusSeconds(3600), "family-a", "user-a");

        int consumed = refreshRepository.consumeIfActive(token.getTokenHash(), now);

        assertThat(consumed).isEqualTo(1);
        assertTokenState(token.getTokenHash(), true);
    }

    @Test
    void consumeIfActiveReturnsZeroWhenTokenWasAlreadyConsumed() {
        RefreshToken token = saveToken("consume-twice", false, now.plusSeconds(3600), "family-a", "user-a");
        assertThat(refreshRepository.consumeIfActive(token.getTokenHash(), now)).isEqualTo(1);
        assertTokenState(token.getTokenHash(), true);

        int consumedAgain = refreshRepository.consumeIfActive(token.getTokenHash(), now);

        assertThat(consumedAgain).isZero();
        assertTokenState(token.getTokenHash(), true);
    }

    @Test
    void consumeIfActiveDoesNotRevokeTokenExpiringExactlyNow() {
        RefreshToken token = saveToken("consume-at-now", false, now, "family-a", "user-a");

        int consumed = refreshRepository.consumeIfActive(token.getTokenHash(), now);

        assertThat(consumed).isZero();
        assertTokenState(token.getTokenHash(), false);
    }

    @Test
    void consumeIfActiveDoesNotChangeAnAlreadyRevokedToken() {
        RefreshToken token = saveToken("consume-revoked", true, now.plusSeconds(3600), "family-a", "user-a");

        int consumed = refreshRepository.consumeIfActive(token.getTokenHash(), now);

        assertThat(consumed).isZero();
        assertTokenState(token.getTokenHash(), true);
    }

    @Test
    void consumeIfActiveClearsCachedTokenStateBeforeSubsequentLookup() {
        RefreshToken token = saveToken("consume-stale-cache", false, now.plusSeconds(3600), "family-a", "user-a");
        RefreshToken initiallyLoaded = refreshRepository.findByTokenHash(token.getTokenHash()).orElseThrow();
        assertThat(initiallyLoaded.isRevoked()).isFalse();

        int consumed = refreshRepository.consumeIfActive(token.getTokenHash(), now);

        Optional<RefreshToken> loadedAfterUpdate = refreshRepository.findByTokenHash(token.getTokenHash());
        assertThat(consumed).isEqualTo(1);
        assertThat(loadedAfterUpdate).isPresent();
        assertThat(loadedAfterUpdate.orElseThrow().isRevoked()).isTrue();
    }

    @Test
    void revokeFamilyRevokesEveryFamilyTokenAndLeavesOtherFamiliesUnchanged() {
        RefreshToken activeFamilyToken = saveToken(
                "family-active", false, now.plusSeconds(3600), "family-target", "user-a");
        RefreshToken expiredFamilyToken = saveToken(
                "family-expired", false, now.minusSeconds(3600), "family-target", "user-a");
        RefreshToken otherFamilyToken = saveToken(
                "family-other", false, now.plusSeconds(3600), "family-other", "user-b");

        int revoked = refreshRepository.revokeFamily("family-target");

        assertThat(revoked).isEqualTo(2);
        assertTokenState(activeFamilyToken.getTokenHash(), true);
        assertTokenState(expiredFamilyToken.getTokenHash(), true);
        assertTokenState(otherFamilyToken.getTokenHash(), false);
    }

    @Test
    void revokeAllByUserIdChangesOnlyUsersActiveNonExpiredTokens() {
        RefreshToken eligibleTokenOne = saveToken(
                "revoke-user-active-one", false, now.plusSeconds(3600), "family-a", "user-target");
        RefreshToken eligibleTokenTwo = saveToken(
                "revoke-user-active-two", false, now.plusSeconds(7200), "family-b", "user-target");
        RefreshToken otherUserToken = saveToken(
                "revoke-other-user", false, now.plusSeconds(3600), "family-c", "user-other");
        RefreshToken expiringNowToken = saveToken(
                "revoke-user-at-now", false, now, "family-d", "user-target");
        RefreshToken previouslyRevokedToken = saveToken(
                "revoke-user-revoked", true, now.plusSeconds(3600), "family-e", "user-target");

        int revoked = refreshRepository.revokeAllByUserId("user-target", now);

        assertThat(revoked).isEqualTo(2);
        assertTokenState(eligibleTokenOne.getTokenHash(), true);
        assertTokenState(eligibleTokenTwo.getTokenHash(), true);
        assertTokenState(otherUserToken.getTokenHash(), false);
        assertTokenState(expiringNowToken.getTokenHash(), false);
        assertTokenState(previouslyRevokedToken.getTokenHash(), true);
    }

    @Test
    void deleteTokenRemovesOnlyRowsStrictlyBeforeCutoff() {
        Instant cutoff = now.minusSeconds(3600);
        RefreshToken beforeCutoff = saveToken(
                "delete-before-cutoff", false, cutoff.minusSeconds(1), "family-a", "user-a");
        RefreshToken atCutoff = saveToken(
                "delete-at-cutoff", false, cutoff, "family-a", "user-a");
        RefreshToken afterCutoff = saveToken(
                "delete-after-cutoff", false, cutoff.plusSeconds(1), "family-a", "user-a");

        int deleted = refreshRepository.deleteToken(cutoff);

        assertThat(deleted).isEqualTo(1);
        assertThat(refreshRepository.findByTokenHash(beforeCutoff.getTokenHash())).isEmpty();
        assertThat(refreshRepository.findByTokenHash(atCutoff.getTokenHash())).isPresent();
        assertThat(refreshRepository.findByTokenHash(afterCutoff.getTokenHash())).isPresent();
    }

    private RefreshToken saveToken(
            String tokenHash,
            boolean revoked,
            Instant expiresAt,
            String familyId,
            String userId) {
        RefreshToken token = new RefreshToken(tokenHash, revoked, expiresAt, familyId, userId);
        RefreshToken savedToken = refreshRepository.save(token);
        entityManager.flush();
        return savedToken;
    }

    private void assertTokenState(String tokenHash, boolean revoked) {
        RefreshToken token = refreshRepository.findByTokenHash(tokenHash).orElseThrow();
        assertThat(token.isRevoked()).isEqualTo(revoked);
    }
}
