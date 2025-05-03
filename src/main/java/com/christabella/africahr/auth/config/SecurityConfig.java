package com.christabella.africahr.auth.config;

import com.christabella.africahr.auth.enums.Roles;
import com.christabella.africahr.auth.security.JwtFilter;
import com.christabella.africahr.auth.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);


    private static final String[] PUBLIC_ENDPOINTS = {"/api/v1/auth/**", "/swagger-ui/**", "/v3/api-docs/**"};
    private static final String ADMIN_ENDPOINT = "/api/v1/auth/users/**";
    private static final String FAVICON = "/favicon.ico";
    private static final String LOGIN_PAGE = "/api/v1/auth/login/google";
    private static final String LOGIN_BASE_URI = "/api/v1/auth/login";
    private static final String CALLBACK_URI = "/api/v1/auth/callback";
    private static final String FRONTEND_LOGIN_ERROR_URL = "http://localhost:5173/login?error=true";
    private static final String FRONTEND_ORIGIN = "http://localhost:5173";

    private final JwtFilter jwtFilter;
    private final AuthService authService;

    public SecurityConfig(JwtFilter jwtFilter, AuthService authService) {
        this.jwtFilter = jwtFilter;
        this.authService = authService;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .requestMatchers(ADMIN_ENDPOINT).hasRole(Roles.ADMIN.name())
                        .requestMatchers(FAVICON).permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth -> oauth
                        .loginPage(LOGIN_PAGE)
                        .authorizationEndpoint(auth -> auth.baseUri(LOGIN_BASE_URI))
                        .redirectionEndpoint(red -> red.baseUri(CALLBACK_URI))
                        .successHandler(oAuth2SuccessHandler())
                        .failureHandler((request, response, exception) -> {
                            logger.error("OAuth2 login failed: {}", exception.getMessage(), exception);
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.sendRedirect(FRONTEND_LOGIN_ERROR_URL);
                        })
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public OAuth2SuccessHandler oAuth2SuccessHandler() {
        return new OAuth2SuccessHandler(authService, objectMapper());
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(FAVICON);
    }

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper().registerModule(new JavaTimeModule());
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(FRONTEND_ORIGIN));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}