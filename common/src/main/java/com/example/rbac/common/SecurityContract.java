package com.example.rbac.common;

import java.util.Set;

/** Shared names and values used by the authentication boundary. */
public final class SecurityContract {
    public static final String ACCESS_TOKEN = "access";
    public static final String REFRESH_TOKEN = "refresh";
    public static final String USER_ID_HEADER = "X-User-Id";
    public static final String USERNAME_HEADER = "X-Username";
    public static final String DEVICE_ID_HEADER = "X-Device-Id";
    public static final String TRACE_ID_HEADER = "X-Trace-Id";
    public static final String INTERNAL_TIMESTAMP_HEADER = "X-Internal-Timestamp";
    public static final String INTERNAL_SIGNATURE_HEADER = "X-Internal-Signature";
    public static final Set<Integer> AUTH_FAILURE_CODES = Set.of(401, 403);

    private SecurityContract() {}
}
