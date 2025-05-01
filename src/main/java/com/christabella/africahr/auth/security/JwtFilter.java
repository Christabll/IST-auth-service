package com.christabella.africahr.auth.security;

import com.christabella.africahr.auth.config.JwtProperties;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    private final JwtProperties jwtProperties;
    private final JwtTokenProvider jwtTokenProvider;
    private static final ThreadLocal<String> tokenHolder = new ThreadLocal<>();

    public JwtFilter(JwtProperties jwtProperties, JwtTokenProvider jwtTokenProvider) {
        this.jwtProperties = jwtProperties;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = resolveToken(request);

        if (token != null) {
            try {
                if (jwtTokenProvider.validateToken(token)) {
                    tokenHolder.set(token);
                    logger.debug("Token extracted and stored: {}", token);

                    String username = jwtTokenProvider.getUsername(token);
                    List<String> roles = jwtTokenProvider.getRoles(token);

                    List<SimpleGrantedAuthority> authorities = roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());

                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                            username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                    logger.debug("Security context set for user: {}", username);
                } else {
                    logger.debug("Token validation failed: {}", token);
                }
            } catch (JwtException e) {
                logger.debug("Token validation failed: {}", e.getMessage());
                SecurityContextHolder.clearContext();
            }
        } else {
            logger.debug("No Authorization header found");
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            tokenHolder.remove();
            SecurityContextHolder.clearContext();
        }
    }

    public static String getToken() {
        return tokenHolder.get();
    }

    private String resolveToken(HttpServletRequest request) {
        if (jwtProperties == null || jwtProperties.getHeader() == null || jwtProperties.getPrefix() == null) {
            logger.error("JwtProperties or its fields are not properly initialized");
            return null;
        }

        String bearerToken = request.getHeader(jwtProperties.getHeader());
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(jwtProperties.getPrefix())) {
            return bearerToken.substring(jwtProperties.getPrefix().length());
        }
        return null;
    }
}