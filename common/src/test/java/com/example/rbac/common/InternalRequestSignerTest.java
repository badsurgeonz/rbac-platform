package com.example.rbac.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InternalRequestSignerTest {
    private static final String SECRET = "internal-test-secret";

    @Test
    void acceptsSignatureWithinTimeWindow() {
        long timestamp = System.currentTimeMillis() / 1000;
        String signature = InternalRequestSigner.sign(SECRET, "GET", "/permissions", timestamp);

        assertTrue(InternalRequestSigner.verify(SECRET, "GET", "/permissions", timestamp, signature, 30));
    }

    @Test
    void rejectsWrongPathSecretAndExpiredTimestamp() {
        long timestamp = System.currentTimeMillis() / 1000;
        String signature = InternalRequestSigner.sign(SECRET, "GET", "/permissions", timestamp);

        assertFalse(InternalRequestSigner.verify(SECRET, "GET", "/other", timestamp, signature, 30));
        assertFalse(InternalRequestSigner.verify("wrong", "GET", "/permissions", timestamp, signature, 30));
        assertFalse(InternalRequestSigner.verify(SECRET, "GET", "/permissions", timestamp - 60, signature, 30));
    }
}
