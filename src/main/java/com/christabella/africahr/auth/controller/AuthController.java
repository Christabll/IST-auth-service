package com.christabella.africahr.auth.controller;

import com.christabella.africahr.auth.dto.*;
import com.christabella.africahr.auth.security.JwtTokenProvider;
import com.christabella.africahr.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthController(AuthService authService, JwtTokenProvider jwtTokenProvider) {
        this.authService = authService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/login/oauth2")
    public ResponseEntity<ApiResponse<AuthResponse>> handleOAuth2Login(OAuth2AuthenticationToken authentication) {
        return ResponseEntity.ok(authService.handleOAuth2Login(authentication));
    }

    @GetMapping("/profile")
    public ResponseEntity<ApiResponse<UserProfileDto>> profile(Authentication authentication) {
        return ResponseEntity.ok(authService.getProfile(authentication.getName()));
    }

    @PostMapping("/validate")
    public ResponseEntity<ApiResponse<TokenValidationResponse>> validateToken() {
        return ResponseEntity.ok(authService.validateToken());
    }

    @PutMapping("/users/{userId}/role")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<ApiResponse<UserProfileDto>> updateRole(
            @PathVariable String userId,
            @RequestBody UpdateRoleRequest req) {
        return ResponseEntity.ok(authService.updateRole(userId, req));
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserProfileDto>>> getAllUsers() {
        return ResponseEntity.ok(ApiResponse.success("All users fetched", authService.getAllUsers()));
    }

    @GetMapping("/users/{userId}/email")
    public ResponseEntity<ApiResponse<String>> getUserEmail(@PathVariable String userId) {
        String email = authService.getUserEmail(userId);
        return ResponseEntity.ok(ApiResponse.success("Email fetched", email));
    }

    @GetMapping("/users/id")
    public ResponseEntity<ApiResponse<String>> getUserIdByEmail(@RequestParam String email) {
        String userId = authService.getUserIdByEmail(email);
        return ResponseEntity.ok(ApiResponse.success("User ID fetched", userId));
    }

    @GetMapping("/users/{userId}/fullname")
    public ResponseEntity<ApiResponse<String>> getUserFullName(@PathVariable String userId) {
        String fullName = authService.getUserFullName(userId);
        return ResponseEntity.ok(ApiResponse.success("Full name fetched", fullName));
    }

    @GetMapping("/users/{userId}/department")
    public ResponseEntity<ApiResponse<String>> getUserDepartment(@PathVariable String userId) {
        String department = authService.getUserDepartment(userId);
        return ResponseEntity.ok(ApiResponse.success("Department fetched", department));
    }

    @PutMapping("/users/{userId}/department")
    public ResponseEntity<ApiResponse<String>> updateDepartment(
            @PathVariable String userId,
            @RequestBody UpdateDepartmentRequest request) {
        String updated = authService.updateDepartment(userId, request.department());
        return ResponseEntity.ok(ApiResponse.success("Department updated", updated));
    }

    @PostMapping("/departments")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<ApiResponse<DepartmentDto>> createDepartment(@RequestBody DepartmentRequestDto dto) {
        return ResponseEntity.ok(ApiResponse.success("Department created", authService.createDepartment(dto)));
    }

    @GetMapping("/departments")
    public ResponseEntity<ApiResponse<List<DepartmentDto>>> getDepartments() {
        return ResponseEntity.ok(ApiResponse.success("Departments fetched", authService.getAllDepartments()));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout() {
        return ResponseEntity.ok(authService.logout());
    }

    @GetMapping("/users/email/{email}")
    public ResponseEntity<ApiResponse<UserProfileDto>> getUserByEmail(@PathVariable String email) {
        return ResponseEntity.ok(authService.getProfile(email));
    }
}