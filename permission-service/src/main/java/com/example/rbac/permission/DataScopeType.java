package com.example.rbac.permission;

public enum DataScopeType {
    ALL,
    SELF,
    DEPARTMENT,
    DEPARTMENT_AND_DESCENDANTS,
    CUSTOM;

    public static DataScopeType parse(String value) {
        try {
            return value == null ? null : valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }
}
