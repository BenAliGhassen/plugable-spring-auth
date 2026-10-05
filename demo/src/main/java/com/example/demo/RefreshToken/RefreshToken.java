package com.example.demo.RefreshToken;

import java.time.Instant;

import com.example.demo.User.User;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String tokenHash;

    private boolean revoked;

    private Instant expiresAt;

    @Column(name = "family_id", length = 36)
    private String familyId;

    @ManyToOne(optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public RefreshToken() {
    }


    public RefreshToken(String tokenHash, boolean revoked, Instant expiresAt, String familyId, User user) {
        this.tokenHash = tokenHash;
        this.revoked = revoked;
        this.expiresAt = expiresAt;
        this.familyId = familyId;
        this.user = user;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String gettokenHash() {
        return tokenHash;
    }

    public void settokenHash(String tokenHash) {
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

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
