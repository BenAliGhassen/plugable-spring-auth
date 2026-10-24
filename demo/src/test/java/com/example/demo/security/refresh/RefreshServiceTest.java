package com.example.demo.security.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import com.example.demo.security.AuthProperties;
import com.example.demo.security.AuthUser;
import com.example.demo.security.AuthUserService;
import com.example.demo.security.DefaultAuthUser;

@ExtendWith(MockitoExtension.class)
class RefreshServiceTest {

    private static final Instant T = Instant.parse("2020-01-01T00:00:00Z");
    private static final String USER_ID = "user-123";
    private static final String USERNAME = "alice@example.com";
    private static final String FAMILY_ID = "family-123";
    private static final String RAW_TOKEN = "known-raw-refresh-token";
    private static final String TOKEN_HASH = sha256(RAW_TOKEN);
    private static final List<SimpleGrantedAuthority> AUTHORITIES = List.of(
            new SimpleGrantedAuthority("ROLE_USER"),
            new SimpleGrantedAuthority("ROLE_ADMIN"));

    @Mock
    private RefreshRepository refreshRepository;

    @Mock
    private AuthUserService authUserService;

    private RefreshService refreshService;

    @BeforeEach
    void setUp() {
        AuthProperties properties = new AuthProperties(
                new AuthProperties.Jwt("test-secret"),
                new AuthProperties.Access(Duration.ofMinutes(15)),
                new AuthProperties.Refresh(Duration.ofDays(3), Duration.ofDays(7)),
                new AuthProperties.Cookie(true),
                new AuthProperties.Cors(List.of("http://localhost:5173")),
                new AuthProperties.Login(5, 20, Duration.ofMinutes(15)));

        refreshService = new RefreshService(
                refreshRepository,
                authUserService,
                properties,
                Clock.fixed(T, ZoneOffset.UTC));
    }

    @Test
    void generateRefreshTokenSavesOnlyHashWithExpectedStateAndExpiry() {
        String rawToken = refreshService.generateRefreshToken(USER_ID);

        ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshRepository).save(tokenCaptor.capture());
        RefreshToken savedToken = tokenCaptor.getValue();

        assertThat(savedToken.getTokenHash()).isEqualTo(sha256(rawToken));
        assertThat(savedToken.isRevoked()).isFalse();
        assertThat(savedToken.getExpiresAt()).isEqualTo(T.plus(Duration.ofDays(7)));
        assertThat(savedToken.getUserId()).isEqualTo(USER_ID);
        assertThat(savedToken.getFamilyId()).isNotBlank();
    }

    @Test
    void generateRefreshTokenCreatesDifferentTokensAndFamiliesForEachCall() {
        String firstRawToken = refreshService.generateRefreshToken(USER_ID);
        String secondRawToken = refreshService.generateRefreshToken(USER_ID);

        ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshRepository, org.mockito.Mockito.times(2)).save(tokenCaptor.capture());
        List<RefreshToken> savedTokens = tokenCaptor.getAllValues();

        assertThat(firstRawToken).isNotEqualTo(secondRawToken);
        assertThat(savedTokens.get(0).getFamilyId())
                .isNotBlank()
                .isNotEqualTo(savedTokens.get(1).getFamilyId());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void generateRefreshTokenRejectsNullOrBlankUserId(String userId) {
        assertThatThrownBy(() -> refreshService.generateRefreshToken(userId))
                .isExactlyInstanceOf(IllegalArgumentException.class);

        verify(refreshRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    void rotateRefreshTokenConsumesActiveTokenAndCreatesReplacementInSameFamily() {
        RefreshToken storedToken = storedToken(false, T.plusSeconds(60), FAMILY_ID);
        when(refreshRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(storedToken));
        when(authUserService.loadUserById(USER_ID)).thenReturn(activeUser());
        when(refreshRepository.consumeIfActive(TOKEN_HASH, T)).thenReturn(1);

        RefreshTokenRotation rotation = refreshService.rotateRefreshToken(RAW_TOKEN);

        ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshRepository).save(tokenCaptor.capture());
        RefreshToken replacement = tokenCaptor.getValue();

        assertThat(rotation.username()).isEqualTo(USERNAME);
        assertThat(rotation.roles()).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
        assertThat(rotation.rawToken()).isNotBlank().isNotEqualTo(RAW_TOKEN);
        assertThat(replacement.getTokenHash()).isEqualTo(sha256(rotation.rawToken()));
        assertThat(replacement.isRevoked()).isFalse();
        assertThat(replacement.getFamilyId()).isEqualTo(FAMILY_ID);
        assertThat(replacement.getExpiresAt()).isEqualTo(T.plus(Duration.ofDays(7)));
        assertThat(replacement.getUserId()).isEqualTo(USER_ID);
        verify(refreshRepository).consumeIfActive(TOKEN_HASH, T);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void rotateRefreshTokenRejectsNullOrBlankRawTokenWithoutRepositoryAccess(String rawToken) {
        assertThatThrownBy(() -> refreshService.rotateRefreshToken(rawToken))
                .isExactlyInstanceOf(InvalidToken.class);

        verifyNoInteractions(refreshRepository);
    }

    @Test
    void rotateRefreshTokenRejectsUnknownTokenWithoutSaving() {
        when(refreshRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshService.rotateRefreshToken(RAW_TOKEN))
                .isExactlyInstanceOf(InvalidToken.class);

        verify(refreshRepository, never()).save(any(RefreshToken.class));
        verify(refreshRepository, never()).consumeIfActive(anyString(), any(Instant.class));
    }

    @Test
    void rotateRefreshTokenRevokesFamilyWhenReusingRevokedToken() {
        RefreshToken revokedToken = storedToken(true, T.plusSeconds(60), FAMILY_ID);
        when(refreshRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(revokedToken));

        assertThatThrownBy(() -> refreshService.rotateRefreshToken(RAW_TOKEN))
                .isExactlyInstanceOf(InvalidToken.class);

        verify(refreshRepository).revokeFamily(FAMILY_ID);
        verify(refreshRepository, never()).save(any(RefreshToken.class));
        verifyNoInteractions(authUserService);
    }

    @Test
    void rotateRefreshTokenRejectsTokenExpiringExactlyAtNowWithoutRevokingFamily() {
        RefreshToken expiredAtBoundary = storedToken(false, T, FAMILY_ID);
        when(refreshRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(expiredAtBoundary));

        assertThatThrownBy(() -> refreshService.rotateRefreshToken(RAW_TOKEN))
                .isExactlyInstanceOf(InvalidToken.class);

        verify(refreshRepository, never()).consumeIfActive(anyString(), any(Instant.class));
        verify(refreshRepository, never()).revokeFamily(anyString());
        verify(refreshRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    void rotateRefreshTokenAcceptsTokenExpiringOneSecondAfterNow() {
        RefreshToken expiringAfterBoundary = storedToken(false, T.plusSeconds(1), FAMILY_ID);
        when(refreshRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(expiringAfterBoundary));
        when(authUserService.loadUserById(USER_ID)).thenReturn(activeUser());
        when(refreshRepository.consumeIfActive(TOKEN_HASH, T)).thenReturn(1);

        RefreshTokenRotation rotation = refreshService.rotateRefreshToken(RAW_TOKEN);

        assertThat(rotation.username()).isEqualTo(USERNAME);
        assertThat(rotation.rawToken()).isNotEqualTo(RAW_TOKEN);
        verify(refreshRepository).consumeIfActive(TOKEN_HASH, T);
    }

    @Test
    void rotateRefreshTokenRejectsDisabledUserWithoutConsumingOrSaving() {
        RefreshToken storedToken = storedToken(false, T.plusSeconds(60), FAMILY_ID);
        when(refreshRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(storedToken));
        when(authUserService.loadUserById(USER_ID)).thenReturn(disabledUser());

        assertThatThrownBy(() -> refreshService.rotateRefreshToken(RAW_TOKEN))
                .isExactlyInstanceOf(DisabledException.class);

        verify(refreshRepository, never()).consumeIfActive(anyString(), any(Instant.class));
        verify(refreshRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    void rotateRefreshTokenRevokesFamilyWhenConcurrentUseFoundRevokedState() {
        RefreshToken activeToken = storedToken(false, T.plusSeconds(60), FAMILY_ID);
        RefreshToken tokenNowRevoked = storedToken(true, T.plusSeconds(60), FAMILY_ID); 
        when(refreshRepository.findByTokenHash(TOKEN_HASH))
                .thenReturn(Optional.of(activeToken)).thenReturn(Optional.of(tokenNowRevoked));
        when(authUserService.loadUserById(USER_ID)).thenReturn(activeUser());
        when(refreshRepository.consumeIfActive(TOKEN_HASH, T)).thenReturn(0);

        assertThatThrownBy(() -> refreshService.rotateRefreshToken(RAW_TOKEN))
                .isExactlyInstanceOf(InvalidToken.class);

        verify(refreshRepository).revokeFamily(FAMILY_ID);
        verify(refreshRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    void rotateRefreshTokenDoesNotRevokeFamilyWhenConcurrentConsumeFailsButTokenIsNotRevoked() {
        RefreshToken activeToken = storedToken(false, T.plusSeconds(60), FAMILY_ID);
        when(refreshRepository.findByTokenHash(TOKEN_HASH))
                .thenReturn(Optional.of(activeToken)).thenReturn(Optional.of(activeToken));
        when(authUserService.loadUserById(USER_ID)).thenReturn(activeUser());
        when(refreshRepository.consumeIfActive(TOKEN_HASH, T)).thenReturn(0);

        assertThatThrownBy(() -> refreshService.rotateRefreshToken(RAW_TOKEN))
                .isExactlyInstanceOf(InvalidToken.class);

        verify(refreshRepository, never()).revokeFamily(anyString());
        verify(refreshRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    void revokeMarksAndSavesActiveToken() {
        RefreshToken activeToken = storedToken(false, T.plusSeconds(60), FAMILY_ID);
        when(refreshRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(activeToken));

        refreshService.revoke(RAW_TOKEN);

        ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshRepository).save(tokenCaptor.capture());
        assertThat(tokenCaptor.getValue().isRevoked()).isTrue();
    }

    @Test
    void revokeRejectsUnknownToken() {
        when(refreshRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshService.revoke(RAW_TOKEN))
                .isExactlyInstanceOf(InvalidToken.class);

        verify(refreshRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    void revokeRejectsAlreadyRevokedToken() {
        RefreshToken revokedToken = storedToken(true, T.plusSeconds(60), FAMILY_ID);
        when(refreshRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(revokedToken));

        assertThatThrownBy(() -> refreshService.revoke(RAW_TOKEN))
                .isExactlyInstanceOf(InvalidToken.class);

        verify(refreshRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    void revokeAllForUserPassesUserIdAndCurrentInstantToRepository() {
        refreshService.revokeAllForUser(USER_ID);

        verify(refreshRepository).revokeAllByUserId(USER_ID, T);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void revokeAllForUserRejectsBlankUserIdWithoutRepositoryAccess(String userId) {
        assertThatThrownBy(() -> refreshService.revokeAllForUser(userId))
                .isExactlyInstanceOf(IllegalArgumentException.class);

        verifyNoInteractions(refreshRepository);
    }

    @Test
    void revokeAllRevokesEveryTokenOwnedByTheCurrentTokenUser() {
        RefreshToken activeToken = storedToken(false, T.plusSeconds(60), FAMILY_ID);
        when(refreshRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(activeToken));

        refreshService.revokeAll(RAW_TOKEN);

        verify(refreshRepository).revokeAllByUserId(USER_ID, T);
    }

    @Test
    void revokeAllRejectsRevokedTokenWithoutRevokingAnyTokens() {
        RefreshToken revokedToken = storedToken(true, T.plusSeconds(60), FAMILY_ID);
        when(refreshRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(revokedToken));

        assertThatThrownBy(() -> refreshService.revokeAll(RAW_TOKEN))
                .isExactlyInstanceOf(InvalidToken.class);

        verify(refreshRepository, never()).revokeAllByUserId(anyString(), any(Instant.class));
    }

    @Test
    void revokeAllRejectsTokenExpiringExactlyAtNowWithoutRevokingAnyTokens() {
        RefreshToken expiresAtBoundary = storedToken(false, T, FAMILY_ID);
        when(refreshRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(expiresAtBoundary));

        assertThatThrownBy(() -> refreshService.revokeAll(RAW_TOKEN))
                .isExactlyInstanceOf(InvalidToken.class);

        verify(refreshRepository, never()).revokeAllByUserId(anyString(), any(Instant.class));
    }

    private RefreshToken storedToken(boolean revoked, Instant expiresAt, String familyId) {
        return new RefreshToken(TOKEN_HASH, revoked, expiresAt, familyId, USER_ID);
    }

    private AuthUser activeUser() {
        return new DefaultAuthUser(USERNAME, "password-hash", AUTHORITIES, USER_ID);
    }

    private AuthUser disabledUser() {
        return new DefaultAuthUser(USERNAME, "password-hash", AUTHORITIES, USER_ID) {
            @Override
            public boolean isEnabled() {
                return false;
            }
        };
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new AssertionError("SHA-256 must be available in the JVM", exception);
        }
    }
}
