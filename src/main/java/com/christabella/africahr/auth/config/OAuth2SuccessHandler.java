package com.christabella.africahr.auth.config;

import com.christabella.africahr.auth.dto.ApiResponse;
import com.christabella.africahr.auth.dto.AuthResponse;
import com.christabella.africahr.auth.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;


@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2SuccessHandler.class);

    private static final String FRONTEND_CALLBACK_URL = "http://localhost:5173/callback";
    private static final String FRONTEND_LOGIN_ERROR_URL = "http://localhost:5173/login?error=true";
    private static final String TOKEN_PARAM = "token";
    private static final String ROLE_PARAM = "role";
    private static final String USER_ID_PARAM = "userId";
    private static final String AVATAR_URL_PARAM = "avatarUrl";

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
            response.sendRedirect(FRONTEND_LOGIN_ERROR_URL);
            return;
        }

        AuthResponse data = authResponse.getData();
        if (data == null) {
            logger.error("OAuth2 login failed: No user data returned");
            response.sendRedirect(FRONTEND_LOGIN_ERROR_URL);
            return;
        }

        String redirectUrl = buildRedirectUrl(data);
        logger.info("Redirecting to frontend with URL: {}", redirectUrl);
        response.sendRedirect(redirectUrl);
    }

    private String buildRedirectUrl(AuthResponse data) {
        StringBuilder redirectUrl = new StringBuilder(FRONTEND_CALLBACK_URL).append("?");
        appendParam(redirectUrl, TOKEN_PARAM, data.token());
        redirectUrl.append("&");
        appendParam(redirectUrl, ROLE_PARAM, data.role());
        redirectUrl.append("&");
        appendParam(redirectUrl, USER_ID_PARAM, data.userId());
        redirectUrl.append("&");
        appendParam(redirectUrl, AVATAR_URL_PARAM, data.avatarUrl());
        return redirectUrl.toString();
    }

    private void appendParam(StringBuilder url, String paramName, String paramValue) {
        url.append(paramName)
                .append("=")
                .append(URLEncoder.encode(paramValue, StandardCharsets.UTF_8));
    }
}