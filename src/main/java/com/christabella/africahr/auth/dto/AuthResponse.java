package com.christabella.africahr.auth.dto;

public record AuthResponse(String token, String role, String avatarUrl, String userId) {

}