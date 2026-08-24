package com.example.rbac.common;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SecurityContractTest {
    @Test
    void createsVersionedEventWithIdAndTimestamp() {
        var event = PermissionEventContract.create("LOGIN_SUCCESS", 7L, null,
                "USER", 7L, "trace-1", Map.of("ip", "127.0.0.1"));

        assertNotNull(event.eventId());
        assertEquals(1, event.eventVersion());
        assertNotNull(event.occurredAt());
        assertEquals("127.0.0.1", event.payload().get("ip"));
    }

    @Test
    void rejectsInvalidEventContract() {
        assertThrows(IllegalArgumentException.class, () -> new PermissionEventContract(
                null, "LOGIN_SUCCESS", 1, null, null, "USER", 7L, null, null, null));
    }
}
