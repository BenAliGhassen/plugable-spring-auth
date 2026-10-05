package com.example.demo.RefreshToken;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findBytokenHash(String tokenHash);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = "UPDATE refresh_tokens SET revoked = true "
            + "WHERE token_hash = :tokenHash AND revoked = false AND expires_at > now()",
            nativeQuery = true)
    int consumeIfActive(@Param("tokenHash") String tokenHash);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = "UPDATE refresh_tokens SET revoked = true WHERE family_id = :familyId",
            nativeQuery = true)
    int revokeFamily(@Param("familyId") String familyId);

}
