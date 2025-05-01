package com.christabella.africahr.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;


@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
        String message,
        T data,
        List<String> errorMessages
) {


    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(message, data, null);
    }


    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(null, data, null);
    }


    public static <T> ApiResponse<T> error(List<String> errorMessages) {
        return new ApiResponse<>(null, null, errorMessages);
    }

    public boolean isSuccess() {
        return errorMessages == null || errorMessages.isEmpty();
    }

    public T getData() {
        return data;
    }

    public List<String> getErrorMessages() {
        return errorMessages;
    }
}