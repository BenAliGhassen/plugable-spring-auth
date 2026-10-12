package com.example.demo.RefreshToken;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

//REFRESH TOKEN REPOSITORY
public interface RefreshRepository extends JpaRepository<RefreshToken, Long> {
        //This query find token by hash
    Optional<RefreshToken> findByTokenHash(String tokenHash);

        //This Atomic Query revoke a token after using the idea is if the user use the refresh token it will be revoked
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = "UPDATE refresh_tokens SET revoked = true "
            + "WHERE token_hash = :tokenHash AND revoked = false AND expires_at > :now",
            nativeQuery = true)
    int consumeIfActive(@Param("tokenHash") String tokenHash, @Param("now") Instant now);

        //This query will revoke all token under the same family it's a security mesure if a token get stolen then the entire family is revoked
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = "UPDATE refresh_tokens SET revoked = true WHERE family_id = :familyId",
            nativeQuery = true)
    int revokeFamily(@Param("familyId") String familyId);

        //This query is used when a profile is locked or a password is changed we revoke all tokens previously owned by this profile
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = "UPDATE refresh_tokens SET revoked = true WHERE user_id = :userId AND revoked = false AND expires_at > NOW()", nativeQuery = true)
    int revokeAllByUserId(@Param("userId") String userId);

        //This query is used in a cron job it delete expired token if they pass a cutoff (expired_at + retention_days)
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = "DELETE FROM refresh_tokens WHERE expires_at < :cutoff", nativeQuery = true)
    int deleteToken(@Param("cutoff")Instant cutoff);


}
