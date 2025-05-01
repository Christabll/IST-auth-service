package com.christabella.africahr.auth.dto;

import java.util.List;

public record UserProfileDto(
        String id,
        String email,
        List<String> roles,
        String avatarUrl
) {
}