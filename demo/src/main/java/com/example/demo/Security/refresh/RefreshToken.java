package com.example.demo.security.refresh;
import java.time.Instant;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

@Entity
@Table(name = "refresh_tokens", indexes = {
@Index(columnList = "family_id"),
@Index(columnList = "user_id"),
@Index(columnList= "expires_at")
}
)
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String tokenHash;

    private boolean revoked;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(name = "family_id", length = 36, nullable = false)
    private String familyId;

    @Column(nullable = false)
    private String userId;

    public RefreshToken() {
    }


    public RefreshToken(String tokenHash, boolean revoked, Instant expiresAt, String familyId,String userId) {
        this.tokenHash = tokenHash;
        this.revoked = revoked;
        this.expiresAt = expiresAt;
        this.familyId = familyId;
        this.userId = userId;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public void setTokenHash(String tokenHash) {
        this.tokenHash = tokenHash;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getFamilyId() {
        return familyId;
    }

    public void setFamilyId(String familyId) {
        this.familyId = familyId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
