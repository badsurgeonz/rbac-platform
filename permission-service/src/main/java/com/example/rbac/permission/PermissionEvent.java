package com.example.rbac.permission;

public record PermissionEvent(Long userId, String action, String subjectType, Long subjectId) {}
