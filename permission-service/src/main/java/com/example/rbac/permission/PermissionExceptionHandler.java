package com.example.rbac.permission;

import com.example.rbac.common.ApiResponse;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class PermissionExceptionHandler {
    @ExceptionHandler({IllegalArgumentException.class, MethodArgumentNotValidException.class})
    public ApiResponse<Void> badRequest(Exception exception) { return ApiResponse.fail(400, exception.getMessage() == null ? "请求参数不合法" : exception.getMessage()); }
}
