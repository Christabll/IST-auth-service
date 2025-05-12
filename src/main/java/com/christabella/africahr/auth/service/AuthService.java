package com.christabella.africahr.auth.service;

import com.christabella.africahr.auth.config.JwtProperties;
import com.christabella.africahr.auth.entity.Department;
import com.christabella.africahr.auth.exception.ResourceNotFoundException;
import com.christabella.africahr.auth.repository.DepartmentRepository;
import com.christabella.africahr.auth.security.JwtFilter;
import com.christabella.africahr.auth.security.JwtTokenProvider;
import com.christabella.africahr.auth.dto.*;
import com.christabella.africahr.auth.entity.BlacklistedToken;
import com.christabella.africahr.auth.entity.User;
import com.christabella.africahr.auth.enums.Roles;
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
    private static final List<String> VALID_ROLES = Arrays.stream(Roles.values())
            .map(Enum::name)
            .toList();

    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtProperties jwtProperties;
    private final BlacklistedTokenRepository blacklistRepo;
    private final DepartmentRepository departmentRepository;

    public AuthService(UserRepository userRepository, JwtTokenProvider jwtTokenProvider,
                       JwtProperties jwtProperties,DepartmentRepository departmentRepository ,BlacklistedTokenRepository blacklistRepo) {
        this.userRepository = userRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtProperties = jwtProperties;
        this.blacklistRepo = blacklistRepo;
        this.departmentRepository = departmentRepository;
    }

    public void saveUser(String email, Roles role, String department, String avatar) {
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    return newUser;
                });

        user.setRoles(role.name());
        user.setDepartment(department);
        user.setAvatarUrl(avatar);
        userRepository.save(user);
        logger.info("Saved user with email: {}, role: {}, department: {}, avatar: {}", email, role, department, avatar);
    }

    public ApiResponse<AuthResponse> handleOAuth2Login(OAuth2AuthenticationToken authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof OidcUser)) {
            return ApiResponse.error(List.of("Unable to authenticate user"));
        }

        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        String email = oidcUser.getEmail();
        String avatar = oidcUser.getPicture();
        String name = oidcUser.getFullName();

        if (email == null || avatar == null) {
            logger.error("Email or avatar not found for user during OAuth2 login");
            return ApiResponse.error(List.of("Missing required user information (email or avatar)"));
        }

        logger.info("Processing OAuth2 login for user: {}", email);

        User user = userRepository.findByEmail(email).orElse(null);
        Roles assignedRole;

        if (user == null) {
            user = new User();
            user.setEmail(email);
            user.setName(name);
            long userCount = userRepository.count();
            assignedRole = (userCount == 0) ? Roles.ADMIN : Roles.STAFF;
            user.setRoles("ROLE_" + assignedRole.name());
        } else {
            String roleStr = user.getRoles().replace("ROLE_", "");
            assignedRole = Roles.valueOf(roleStr.toUpperCase());
        }

        user.setDepartment(null);
        user.setAvatarUrl(avatar);
        userRepository.save(user);

        List<String> roles = Arrays.asList(user.getRoles().split(","));
        String token = jwtTokenProvider.generateToken(user.getEmail(), roles);

        AuthResponse authResponse = new AuthResponse(token, assignedRole.name(), avatar, user.getId());
        return ApiResponse.success("User logged in successfully", authResponse);
    }

    public ApiResponse<UserProfileDto> getProfile(String email) {
        return userRepository.findByEmail(email)
                .map(user -> {
                    List<String> roles = Arrays.stream(user.getRoles().split(","))
                            .map(String::trim)
                            .map(role -> role.replace("ROLE_", ""))
                            .toList();
                    return ApiResponse.success("User profile retrieved successfully",
                            new UserProfileDto(user.getId(), user.getEmail(), roles, user.getAvatarUrl(),user.getDepartment()));
                })
                .orElseGet(() -> {
                    logger.warn("Profile retrieval failed - user not found with email: {}", email);
                    return ApiResponse.error(List.of("User profile not found"));
                });
    }


    public List<UserProfileDto> getAllUsers() {
        List<User> users = userRepository.findAll();
        return users.stream()
                .map(user -> UserProfileDto.from(user))
                .toList();
    }

    public ApiResponse<TokenValidationResponse> validateToken() {
        String token = JwtFilter.getToken();

        if (token == null) {
            logger.debug("No token provided");
            return ApiResponse.error(List.of("Authentication token is required"));
        }

        try {
            if (!jwtTokenProvider.validateToken(token)) {
                logger.debug("Token validation failed - invalid token: {}", token);
                return ApiResponse.error(List.of("Invalid authentication token"));
            }
        } catch (JwtException e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return ApiResponse.error(List.of("Invalid authentication token: " + e.getMessage()));
        }

        if (blacklistRepo.existsByToken(token)) {
            logger.debug("Token validation failed - token is blacklisted: {}", token);
            return ApiResponse.error(List.of("Authentication token has been invalidated"));
        }

        logger.debug("Token validated successfully");
        return ApiResponse.success("Authentication token is valid", new TokenValidationResponse(true));
    }

    
    public ApiResponse<UserProfileDto> updateRole(String userId, UpdateRoleRequest updateRoleRequest) {
        return userRepository.findById(userId)
                .map(user -> {
                    user.setRoles(updateRoleRequest.role().name());
                    userRepository.save(user);
                    logger.debug("Role updated successfully for the userId: {}", userId);
                    List<String> roles = Arrays.asList(user.getRoles().split(","));
                    return ApiResponse.success("User role updated successfully",
                            new UserProfileDto(user.getId(), user.getEmail(), roles, user.getAvatarUrl(),user.getDepartment()));
                })
                .orElseGet(() -> {
                    logger.warn("Role update failed - user not found with ID: {}", userId);
                    return ApiResponse.error(List.of("User not found for role update"));
                });
    }


    public String getUserEmail(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return user.getEmail();
    }

    public String getUserFullName(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return user.getName();
    }


    public String getUserDepartment(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return user.getDepartment();
    }


    public String updateDepartment(String userId, String department) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        user.setDepartment(department);
        userRepository.save(user);
        return department;
    }


    public DepartmentDto createDepartment(DepartmentRequestDto dto) {
        if (departmentRepository.existsByName(dto.name())) {
            throw new IllegalArgumentException("Department already exists");
        }

        Department saved = departmentRepository.save(
                Department.builder().name(dto.name()).build()
        );

        return new DepartmentDto(saved.getId(), saved.getName());
    }


    public List<DepartmentDto> getAllDepartments() {
        return departmentRepository.findAll().stream()
                .map(dep -> new DepartmentDto(dep.getId(), dep.getName()))
                .toList();
    }



    public ApiResponse<Void> logout() {
        String token = JwtFilter.getToken();
        if (token == null) {
            logger.debug("No token provided for logout");
            return ApiResponse.error(List.of("Authentication token is required for logout"));
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
