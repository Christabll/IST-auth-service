//package com.christabella.africahr.auth_service;
//
//
//import com.christabella.africahr.auth.dto.UpdateRoleRequest;
//import com.christabella.africahr.auth.entity.User;
//import com.christabella.africahr.auth.repository.BlacklistedTokenRepository;
//import com.christabella.africahr.auth.repository.UserRepository;
//import com.christabella.africahr.auth.security.JwtTokenProvider;
//import com.fasterxml.jackson.databind.ObjectMapper;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.http.MediaType;
//import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
//import org.springframework.security.oauth2.core.user.OAuth2User;
//import org.springframework.test.web.servlet.MockMvc;
//
//import java.util.Collections;
//import java.util.HashMap;
//import java.util.List;
//
//import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
//import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
//import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
//
//@SpringBootTest
//@AutoConfigureMockMvc
//public class AuthControllerTest {
//
//    @Autowired
//    private MockMvc mockMvc;
//
//    @Autowired
//    private UserRepository userRepo;
//
//    @Autowired
//    private BlacklistedTokenRepository blacklistRepo;
//
//    @Autowired
//    private JwtTokenProvider jwtProvider;
//
//    @Autowired
//    private ObjectMapper objectMapper;
//
//    private OAuth2User oAuth2User;
//    private String token;
//    private User user;
//
//    @BeforeEach
//    void setUp() {
//        blacklistRepo.deleteAll();
//        userRepo.deleteAll();
//
//
//        HashMap<String, Object> attributes = new HashMap<>();
//        attributes.put("email", "test@example.com");
//        attributes.put("picture", "https://example.com/avatar.jpg");
//        oAuth2User = new DefaultOAuth2User(Collections.emptyList(), attributes, "email");
//
//
//        user = User.builder()
//                .email("test@example.com")
//                .roles("ROLE_STAFF")
//                .avatarUrl("https://example.com/avatar.jpg")
//                .build();
//        userRepo.save(user);
//
//
//        token = jwtProvider.generateToken("test@example.com", List.of("ROLE_STAFF"), "https://example.com/avatar.jpg");
//    }
//
//    @Test
//    void testLogin() throws Exception {
//        mockMvc.perform(get("/api/v1/auth/login"))
//                .andExpect(status().isFound());
//    }
//
//    @Test
//    void testCallback() throws Exception {
//        mockMvc.perform(get("/api/v1/auth/callback")
//                        .with(oauth2Login().oauth2User(oAuth2User)))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.token").exists())
//                .andExpect(jsonPath("$.profile.email").value("test@example.com"))
//                .andExpect(jsonPath("$.profile.avatarUrl").value("https://example.com/avatar.jpg"))
//                .andExpect(jsonPath("$.profile.roles[0]").value("ROLE_STAFF"));
//    }
//
//    @Test
//    void testProfile() throws Exception {
//        mockMvc.perform(get("/api/v1/auth/profile")
//                        .header("Authorization", "Bearer " + token))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.email").value("test@example.com"))
//                .andExpect(jsonPath("$.roles[0]").value("ROLE_STAFF"))
//                .andExpect(jsonPath("$.avatarUrl").value("https://example.com/avatar.jpg"));
//    }
//
//    @Test
//    void testValidateToken() throws Exception {
//        mockMvc.perform(post("/api/v1/auth/validate")
//                        .header("Authorization", "Bearer " + token))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.valid").value(true))
//                .andExpect(jsonPath("$.email").value("test@example.com"))
//                .andExpect(jsonPath("$.roles[0]").value("ROLE_STAFF"));
//    }
//
//    @Test
//    void testUpdateRole() throws Exception {
//
//        User admin = User.builder()
//                .email("admin@example.com")
//                .roles("ROLE_ADMIN")
//                .avatarUrl("https://example.com/admin.jpg")
//                .build();
//        userRepo.save(admin);
//        String adminToken = jwtProvider.generateToken("admin@example.com", List.of("ROLE_ADMIN"), "https://example.com/admin.jpg");
//
//        UpdateRoleRequest request = new UpdateRoleRequest("ADMIN");
//        mockMvc.perform(put("/api/v1/auth/users/" + user.getId() + "/role")
//                        .header("Authorization", "Bearer " + adminToken)
//                        .contentType(MediaType.APPLICATION_JSON)
//                        .content(objectMapper.writeValueAsString(request)))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.roles").value(List.of("ROLE_STAFF", "ROLE_ADMIN")));
//    }
//
//    @Test
//    void testLogout() throws Exception {
//        mockMvc.perform(post("/api/v1/auth/logout")
//                        .header("Authorization", "Bearer " + token))
//                .andExpect(status().isOk());
//
//
//        mockMvc.perform(post("/api/v1/auth/validate")
//                        .header("Authorization", "Bearer " + token))
//                .andExpect(status().isUnauthorized())
//                .andExpect(jsonPath("$.message").value("Token is blacklisted"));
//    }
//}