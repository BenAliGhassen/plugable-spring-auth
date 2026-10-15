package com.example.demo.security.refresh;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.demo.security.AuthProperties;
import com.example.demo.security.AuthUser;
import com.example.demo.security.AuthUserService;
import com.example.demo.security.AuthorityMapper;

//THIS FILE IS RESPONSIBLE FOR GENERATING A REFRESH TOKEN, ROTATE IT AND REVOKE IT
@Service
public class RefreshService {

    private static final int TOKEN_LENGTH_BYTES = 64;
    private final AuthProperties authProps;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private final RefreshRepository refreshRepo;
    private final AuthUserService authService;

    public RefreshService(RefreshRepository refreshRepo, AuthUserService authService, AuthProperties authProps) {
        this.refreshRepo = refreshRepo;
        this.authService = authService;
        this.authProps = authProps;
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

/*CREATE A RANDOM BYTE STRING RAW TOKEN OF 64 BYTE */
    private String createRawToken() {
        byte[] randomBytes = new byte[TOKEN_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }


/*METHODE TO BE CALLED IN LOGIN METHODE IN USER CONTROLLER TAKE USER_Id AS PARAM RETURN A CALL TO THE REAL GENERATION METHODE WITH USER AND FAMILY_ID */
    public String generateRefreshToken(String userId) {
        return issueToken(userId, generateFamilyId());
    }


/*GENERATE REFRESH TOKEN */
    private String issueToken(String userId, String familyId) {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("User must not be null");
        }
        if (familyId == null || familyId.isBlank()) {
            throw new IllegalArgumentException("Family ID must not be null or blank");
        }

        String rawToken = createRawToken();
        refreshRepo.save(new RefreshToken(hash(rawToken), false, Instant.now().plus(authProps.refresh().ttl()), familyId, userId));
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
        RefreshToken currentToken = refreshRepo.findByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidToken("Invalid refresh token"));

        if (currentToken.isRevoked()) {
            revokeTokenFamily(currentToken);
            throw new InvalidToken("Invalid refresh token");
        }

        if (currentToken.getExpiresAt() == null || !currentToken.getExpiresAt().isAfter(now)) {
            throw new InvalidToken("Invalid refresh token");
        }
        //Find by uuid
        AuthUser authUser = authService.loadUserById(currentToken.getUserId());
        //check the account is not disabled or expired
        new AccountStatusUserDetailsChecker().check(authUser);
        List<String> roles = AuthorityMapper.toRoleNames(authUser.getAuthorities());
        String username = authUser.getUsername();
        String familyId = currentToken.getFamilyId();
        String userId = currentToken.getUserId();

        if (familyId == null || familyId.isBlank()) {
            throw new InvalidToken("Invalid refresh token");
        }

        if (refreshRepo.consumeIfActive(tokenHash, now) != 1) {
            RefreshToken latestToken = refreshRepo.findByTokenHash(tokenHash)
                    .orElseThrow(() -> new InvalidToken("Invalid refresh token"));
            if (latestToken.isRevoked()) {
                revokeTokenFamily(latestToken);
            }
            throw new InvalidToken("Invalid refresh token");
        }

        String replacementRawToken = issueToken(userId, familyId);
        
        return new RefreshTokenRotation(username, roles, replacementRawToken);
    }

/*REVOKE METHODE SEARCH FOR THE TOKEN AND SET IT TO REVOKED. THIS METHODE IS CALLED ON LOGOUT IN AuthController*/
    public void revoke(String raw) {
        String tokenHash = hash(raw);
        RefreshToken refreshToken = refreshRepo.findByTokenHash(tokenHash)
                .filter(token -> !token.isRevoked())
                .orElseThrow(() -> new InvalidToken("Invalid refresh token"));

        refreshToken.setRevoked(true);
        refreshRepo.save(refreshToken);
    }

/*THIS METHODE IS USED WHEN A USER CHANGE HIS PASSWORD */  
    @Transactional          
    public void revokeAllForUser(String userId){
        if(userId == null || userId.isBlank()){
            throw new IllegalArgumentException("User id must not be blank");
        }
        refreshRepo.revokeAllByUserId(userId);
    } 
    
/*THIS METHODE IS USED WHEN A LOGOUT ALL IS CLICKED */
    @Transactional
    public void revokeAll(String raw){
        String tokenHash = hash(raw);
        RefreshToken refreshToken = refreshRepo.findByTokenHash(tokenHash).filter(token -> !token.isRevoked() && token.getExpiresAt().isAfter(Instant.now())).orElseThrow(() -> new InvalidToken("Invalid refresh token"));       
        revokeAllForUser(refreshToken.getUserId());
            }       
}
