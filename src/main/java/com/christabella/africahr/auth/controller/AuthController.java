package com.christabella.africahr.auth.controller;

import com.christabella.africahr.auth.dto.*;
import com.christabella.africahr.auth.security.JwtTokenProvider;
import com.christabella.africahr.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.*;



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
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<UserProfileDto>> updateRole(
            @PathVariable String userId,
            @RequestBody UpdateRoleRequest req) {
        return ResponseEntity.ok(authService.updateRole(userId, req));
    }


    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout() {
        return ResponseEntity.ok(authService.logout());
    }

}