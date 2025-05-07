package com.christabella.africahr.auth.exception;

import com.christabella.africahr.auth.dto.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.List;

@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidCredentials(InvalidCredentialsException ex) {
        logger.warn("Invalid credentials: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error(List.of(ex.getMessage())));
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleUserNotFound(UserNotFoundException ex) {
        logger.warn("User not found: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.error(List.of(ex.getMessage())));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Void>> handleBadRequest(IllegalArgumentException ex) {
        logger.warn("Bad request: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(List.of(ex.getMessage())));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleAllUnhandled(Exception ex) {
        logger.error("Unexpected error: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error(List.of("An unexpected error occurred")));
    }
}
