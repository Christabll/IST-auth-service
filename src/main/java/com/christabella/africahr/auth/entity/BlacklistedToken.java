package com.christabella.africahr.auth.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Entity
@Data
@Builder

public class BlacklistedToken {
    @Id
    private String token;
    private Instant expiresAt;

    public BlacklistedToken() {}

    public BlacklistedToken(String token, Instant expiresAt) {
        this.token = token;
        this.expiresAt = expiresAt;
    }
}