package com.christabella.africahr.auth.config;

import com.christabella.africahr.auth.dto.ApiResponse;
import com.christabella.africahr.auth.dto.AuthResponse;
import com.christabella.africahr.auth.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2SuccessHandler.class);

    private final AuthService authService;
    private final ObjectMapper objectMapper;

    public OAuth2SuccessHandler(AuthService authService, ObjectMapper objectMapper) {
        this.authService = authService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

        logger.info("OAuth2 login successful for user: {}", authentication.getPrincipal());

        ApiResponse<AuthResponse> authResponse = authService.handleOAuth2Login(oauthToken);

        if (!authResponse.isSuccess()) {
            logger.error("OAuth2 login failed: {}", authResponse.getErrorMessages());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "OAuth2 login failed");
            return;
        }

        String token = authResponse.getData().token();
        String role = authResponse.getData().role();

        String frontendRedirect = "http://localhost:4200/auth/callback?token=" + token + "&role=" + role;
        response.sendRedirect(frontendRedirect);

    }
}
