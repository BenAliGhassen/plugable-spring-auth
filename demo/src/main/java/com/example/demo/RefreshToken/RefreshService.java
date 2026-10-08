package com.example.demo.RefreshToken;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.demo.Security.AuthUser;
import com.example.demo.Security.AuthUserService;
import com.example.demo.Security.AuthorityMapper;

@Service
public class RefreshService {

    private static final int TOKEN_LENGTH_BYTES = 64;
    public static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(7);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RefreshRepository refreshRepo;
    private final AuthUserService authService;

    public RefreshService(RefreshRepository refreshRepo, AuthUserService authService) {
        this.refreshRepo = refreshRepo;
        this.authService = authService;
    }


  /* HASH METHODE TO HASH REFRESH TOKEN */
    private String hash(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Value to hash must not be null");
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        }catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }


/*REVOKE FAMILY CALL ATOMIC QUERY TO REVOKE ALL TOKEN HAVING THE SAME FAMILY_ID */
    private void revokeTokenFamily(RefreshToken token) {
        if (token.getFamilyId() != null && !token.getFamilyId().isBlank()) {
            refreshRepo.revokeFamily(token.getFamilyId());
        }
    }

/*CREATE A RANDOM BYTE STRING RAW TOKEN OF 32 BYTE */
    private String createRawToken() {
        byte[] randomBytes = new byte[TOKEN_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }


/*METHODE TO BE CALLED IN LOGIN METHODE IN USER CONTROLLER TAKE USER SUBJECT AS PARAM RETURN A CALL TO THE REAL GENERATION METHODE WITH USER AND FAMILY_ID */
    public String generateRefreshToken(String userId) {
        return issueToken(userId, generateFamilyId());
    }


/*GENERATE REFRESH TOKEN */
    private String issueToken(String user_id, String familyId) {
        if (user_id == null || user_id == "") {
            throw new IllegalArgumentException("User must not be null");
        }
        if (familyId == null || familyId.isBlank()) {
            throw new IllegalArgumentException("Family ID must not be null or blank");
        }

        String rawToken = createRawToken();
        refreshRepo.save(new RefreshToken(hash(rawToken), false, Instant.now().plus(REFRESH_TOKEN_TTL), familyId, user_id));
        return rawToken;
    }


/*GENERATE UNIQUE ID*/
    private String generateFamilyId() {
        return UUID.randomUUID().toString();
    }


/*REFRESH TOKEN CHECK THAT THE TOKEN IS VALID BY CHECKING IT'S EXPIRED IF REVOKED OR NOT IN DB THEN THROW ERROR IS EXPIRED THEN ROTATE(CREATE A NEW TOKEN AND MARK THE OLD AS REVOKED = TRUE).
IT USE TWO ATOMIC QUERY ONE IS REVOKE FAMILY IF CURRENT TOKEN IS REVOKED (REASON IS NO LEGIT USER WILL SEND A REVOKE TOKEN SO IT'S STOLEN ONE).
SECOND ATOMIC IS CONSUMEIFACTIVE IT HANDLE RACE CONDITION IF TWO REQ WITH SAME TOKEN HIT THE DB THE WINNER WILL UPDATE THE TOKEN THE SECOND WILL NOT TOUCH IT AS IT WILL GET CHANGED ROWS = 0 */
@Transactional(noRollbackFor = InvalidToken.class)
    public RefreshTokenRotation rotateRefreshToken(String rawToken) {

        if (rawToken == null || rawToken.isBlank()) {
            throw new InvalidToken("Invalid refresh token");
        }

        String tokenHash = hash(rawToken);
        Instant now = Instant.now();
        RefreshToken currentToken = refreshRepo.findBytokenHash(tokenHash)
                .orElseThrow(() -> new InvalidToken("Invalid refresh token"));

        if (currentToken.isRevoked()) {
            revokeTokenFamily(currentToken);
            throw new InvalidToken("Invalid refresh token");
        }

        if (currentToken.getExpiresAt() == null || !currentToken.getExpiresAt().isAfter(now)) {
            throw new InvalidToken("Invalid refresh token");
        }
        //Find by uuid
        AuthUser authuser = authService.loadUserById(currentToken.getUser());
        new AccountStatusUserDetailsChecker().check(authuser);
        List<String> roles = AuthorityMapper.toRoleName(authuser.getAuthorities());
        String username = authuser.getUsername();
        String familyId = currentToken.getFamilyId();
        String user_id = currentToken.getUser();

        if (familyId == null || familyId.isBlank()) {
            throw new InvalidToken("Invalid refresh token");
        }

        if (refreshRepo.consumeIfActive(tokenHash) != 1) {
            RefreshToken latestToken = refreshRepo.findBytokenHash(tokenHash)
                    .orElseThrow(() -> new InvalidToken("Invalid refresh token"));
            if (latestToken.isRevoked()) {
                revokeTokenFamily(latestToken);
            }
            throw new InvalidToken("Invalid refresh token");
        }

        String replacementRawToken = issueToken(user_id, familyId);
        
        return new RefreshTokenRotation(username, roles, replacementRawToken);
    }

/*REVOKE METHODE SEARCH FOR THE TOKEN AND SET IT TO REVOKED. THIS METHODE IS CALLED ON LOGOUT IN USER SERVICE*/
    public void revoke(String raw) {
        String tokenHash = hash(raw);
        RefreshToken refreshToken = refreshRepo.findBytokenHash(tokenHash)
                .filter(token -> !token.isRevoked())
                .orElseThrow(() -> new InvalidToken("Invalid refresh token"));

        refreshToken.setRevoked(true);
        refreshRepo.save(refreshToken);
    }
}
