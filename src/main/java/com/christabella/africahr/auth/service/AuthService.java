package com.christabella.africahr.auth.service;

import com.christabella.africahr.auth.config.JwtProperties;
import com.christabella.africahr.auth.security.JwtFilter;
import com.christabella.africahr.auth.security.JwtTokenProvider;
import com.christabella.africahr.auth.dto.*;
import com.christabella.africahr.auth.entity.BlacklistedToken;
import com.christabella.africahr.auth.entity.User;
import com.christabella.africahr.auth.repository.BlacklistedTokenRepository;
import com.christabella.africahr.auth.repository.UserRepository;
import io.jsonwebtoken.JwtException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;


@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private static final List<String> VALID_ROLES = List.of("Admin", "Staff", "Manager");

    private final UserRepository userRepo;
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtProperties jwtProperties;
    private final BlacklistedTokenRepository blacklistRepo;


    public AuthService(UserRepository userRepo, JwtTokenProvider jwtTokenProvider, JwtProperties jwtProperties, BlacklistedTokenRepository blacklistRepo) {
        this.userRepo = userRepo;
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtProperties = jwtProperties;
        this.blacklistRepo = blacklistRepo;
    }

    public void saveUser(String email, String role, String department, String avatar) {
        User user = userRepo.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    return newUser;
                });

        user.setRoles("ROLE_" + role);
        user.setDepartment(department);
        user.setAvatarUrl(avatar);
        userRepo.save(user);
        logger.info("Saved user with email: {}, role: {}, department: {}, avatar: {}", email, role, department, avatar);
    }


    public ApiResponse<AuthResponse> handleOAuth2Login(OAuth2AuthenticationToken authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof OidcUser)) {
            return ApiResponse.error(Arrays.asList("Unable to authenticate user"));
        }

        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        String email = oidcUser.getEmail();
        String avatar = oidcUser.getPicture();
        String name = oidcUser.getFullName();

        if (email == null || avatar == null) {
            logger.error("Email or avatar not found for user during OAuth2 login");
            return ApiResponse.error(Arrays.asList("Missing required user information (email or avatar)"));
        }

        logger.info("Processing OAuth2 login for user: {}", email);

        User user = userRepo.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setName(name);
                    return newUser;
                });

        String role;
        long userCount = userRepo.count();
        if (userCount == 0) {
            role = "Admin";
        } else {
            role = "Staff";
        }

        String department = null;
        user.setRoles("ROLE_" + role);
        user.setDepartment(department);
        user.setAvatarUrl(avatar);
        userRepo.save(user);

        List<String> roles = Arrays.asList(user.getRoles().split(","));
        String token = jwtTokenProvider.generateToken(user.getEmail(), roles);

        String roleWithoutPrefix = role.substring(0, 1).toUpperCase() + role.substring(1).toLowerCase();
        AuthResponse authResponse = new AuthResponse(token, roleWithoutPrefix, avatar, user.getId());
        return ApiResponse.success("User logged in successfully", authResponse);
    }


    public ApiResponse<UserProfileDto> getProfile(String email) {
        return userRepo.findByEmail(email)
                .map(user -> {
                    List<String> roles = Arrays.stream(user.getRoles().split(","))
                            .map(String::trim)
                            .map(role -> role.replace("ROLE_", ""))
                            .toList();
                    return ApiResponse.success("User profile retrieved successfully", new UserProfileDto(user.getId(), user.getEmail(), roles, user.getAvatarUrl()));
                })
                .orElseGet(() -> {
                    logger.warn("Profile retrieval failed - user not found with email: {}", email);
                    return ApiResponse.error(Arrays.asList("User profile not found"));
                });
    }


    public ApiResponse<TokenValidationResponse> validateToken() {
        String token = JwtFilter.getToken();

        if (token == null) {
            logger.debug("No token provided");
            return ApiResponse.error(Arrays.asList("Authentication token is required"));
        }

        try {
            if (!jwtTokenProvider.validateToken(token)) {
                logger.debug("Token validation failed - invalid token: {}", token);
                return ApiResponse.error(Arrays.asList("Invalid authentication token"));
            }
        } catch (JwtException e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return ApiResponse.error(Arrays.asList("Invalid authentication token: " + e.getMessage()));
        }

        if (blacklistRepo.existsByToken(token)) {
            logger.debug("Token validation failed - token is blacklisted: {}", token);
            return ApiResponse.error(Arrays.asList("Authentication token has been invalidated"));
        }

        logger.debug("Token validated successfully");
        return ApiResponse.success("Authentication token is valid", new TokenValidationResponse(true));
    }


    public ApiResponse<UserProfileDto> updateRole(String userId, UpdateRoleRequest updateRoleRequest) {
        return userRepo.findById(userId)
                .map(user -> {
                    user.setRoles("ROLE_" + updateRoleRequest.role());
                    userRepo.save(user);
                    logger.debug("Role updated successfully for the userId: {}", userId);
                    List<String> roles = Arrays.asList(user.getRoles().split(","));
                    return ApiResponse.success("User role updated successfully", new UserProfileDto(user.getId(), user.getEmail(), roles, user.getAvatarUrl()));
                })
                .orElseGet(() -> {
                    logger.warn("Role update failed - user not found with ID: {}", userId);
                    return ApiResponse.error(Arrays.asList("User not found for role update"));
                });
    }


    public ApiResponse<Void> logout() {
        String token = JwtFilter.getToken();
        if (token == null) {
            logger.debug("No token provided for logout");
            return ApiResponse.error(Arrays.asList("Authentication token is required for logout"));
        }

        Date expiry = jwtTokenProvider.getExpiration(token);
        Instant expiresAt = expiry.toInstant();

        blacklistRepo.save(BlacklistedToken.builder()
                .token(token)
                .expiresAt(expiresAt)
                .build());

        logger.info("Token blacklisted successfully: {}", token);
        return ApiResponse.success("User logged out successfully", null);
    }


}

