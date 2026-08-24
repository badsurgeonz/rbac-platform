package com.example.rbac.common;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record PermissionEventContract(
        UUID eventId,
        String eventType,
        int eventVersion,
        Long userId,
        Long operatorId,
        String subjectType,
        Long subjectId,
        Instant occurredAt,
        String traceId,
        Map<String, Object> payload) {

    public PermissionEventContract {
        if (eventId == null) throw new IllegalArgumentException("eventId is required");
        if (eventType == null || eventType.isBlank()) throw new IllegalArgumentException("eventType is required");
        if (eventVersion < 1) throw new IllegalArgumentException("eventVersion must be positive");
        if (occurredAt == null) throw new IllegalArgumentException("occurredAt is required");
        payload = payload == null ? Map.of() : Map.copyOf(payload);
    }

    public static PermissionEventContract create(String eventType, Long userId, Long operatorId,
                                                  String subjectType, Long subjectId, String traceId,
                                                  Map<String, Object> payload) {
        return new PermissionEventContract(UUID.randomUUID(), eventType, 1, userId, operatorId,
                subjectType, subjectId, Instant.now(), traceId, payload);
    }
}
