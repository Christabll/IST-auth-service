package com.christabella.africahr.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.List;

@Configuration
public class SwaggerConfig {

    private static final List<String> PUBLIC_PATHS = Arrays.asList(
            "/api/v1/auth/login",
            "/api/v1/auth/callback"
    );

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Authentication Service API")
                        .version("1.0.0")
                        .description("API for user authentication in the Leave Management System. Supports Google OAuth2 login, token validation, user role management (Staff, Manager, Admin), and profile retrieval. " +
                                "To authenticate, access `/api/v1/auth/login` in a browser to initiate Google OAuth2 login. After successful login, you’ll be redirected to `/api/v1/auth/callback`, which returns a JWT token, user role, and avatar URL. " +
                                "Use the JWT token in the `Authorization` header (e.g., `Bearer <token>`) for authenticated endpoints like `/profile`, `/logout`, `/validate`, and `/users/{userId}/role`."))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")));
    }

    @Bean
    public OpenApiCustomizer globalResponsesCustomizer() {
        return openApi -> openApi.getPaths().forEach((path, pathItem) -> {
            if (!PUBLIC_PATHS.contains(path)) {
                pathItem.readOperations().forEach(operation ->
                        operation.addSecurityItem(new SecurityRequirement().addList("bearerAuth")));
            }

            pathItem.readOperations().forEach(operation -> {
                ApiResponses apiResponses = operation.getResponses();
                if (apiResponses == null) {
                    apiResponses = new ApiResponses();
                    operation.setResponses(apiResponses);
                }

                ApiResponse successResponse = new ApiResponse()
                        .description("Successful operation")
                        .content(new Content().addMediaType("application/json",
                                new MediaType().schema(new Schema<>().$ref("#/components/schemas/ApiResponse"))));
                apiResponses.addApiResponse("200", successResponse);
            });
        });
    }

    @Bean
    public OpenApiCustomizer addSchemas() {
        return openApi -> {
            Components components = openApi.getComponents();
            if (components == null) {
                components = new Components();
                openApi.setComponents(components);
            }
            components.addSchemas("ApiResponse", new Schema<>()
                    .type("object")
                    .addProperty("message", new Schema<>().type("string"))
                    .addProperty("data", new Schema<>().type("object"))
                    .addProperty("errors", new Schema<>().type("array").items(new Schema<>().type("string"))));
        };
    }
}