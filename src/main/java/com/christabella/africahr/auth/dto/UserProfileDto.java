package com.christabella.africahr.auth.dto;

import com.christabella.africahr.auth.entity.User;

import java.util.Arrays;
import java.util.List;

public record UserProfileDto(
        String id,
        String email,
        List<String> roles,
        String avatarUrl,
        String department
) {
    public static UserProfileDto from(User user) {
        List<String> roles = Arrays.stream(user.getRoles().split(","))
                .map(String::trim)
                .map(role -> {
                    String cleaned = role.replace("ROLE_", "").toUpperCase();
                    return switch (cleaned) {
                        case "ADMIN" -> "Admin";
                        case "MANAGER" -> "Manager";
                        case "STAFF" -> "Staff";
                        default -> cleaned.charAt(0) + cleaned.substring(1).toLowerCase();
                    };
                })
                .toList();

        return new UserProfileDto(
                user.getId(),
                user.getEmail(),
                roles,
                user.getAvatarUrl(),
                user.getDepartment()
        );
    }

}
