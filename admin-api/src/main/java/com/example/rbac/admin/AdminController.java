package com.example.rbac.admin;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
public class AdminController {
    private final AdminBackendClient backend;
    public AdminController(AdminBackendClient backend) { this.backend = backend; }

    @GetMapping("/users")
    public JsonNode users() { return backend.get("auth-service", "/auth/internal/users"); }

    @PutMapping("/users/{userId}/status")
    public JsonNode changeStatus(@PathVariable Long userId, @RequestParam int status,
                                 @RequestHeader("X-User-Id") Long operatorId,
                                 @RequestHeader("X-Step-Up-Token") String stepUpToken) {
        return backend.putAsOperator("auth-service", "/auth/internal/users/" + userId + "/status", java.util.Map.of("status", status, "stepUpToken", stepUpToken), operatorId, stepUpToken);
    }

    @GetMapping("/roles")
    public JsonNode roles() { return backend.get("permission-service", "/permissions/internal/roles"); }

    @PostMapping("/roles")
    public JsonNode createRole(@RequestBody Object request) { return backend.post("permission-service", "/permissions/roles", request); }

    @GetMapping("/permissions")
    public JsonNode permissions() { return backend.get("permission-service", "/permissions"); }

    @PostMapping("/permissions")
    public JsonNode createPermission(@RequestBody Object request) { return backend.post("permission-service", "/permissions", request); }

    @PutMapping("/roles/{roleId}/permissions")
    public JsonNode replaceRolePermissions(@PathVariable Long roleId, @RequestBody Object request) {
        return backend.put("permission-service", "/permissions/roles/" + roleId + "/permissions", request);
    }

    @GetMapping("/data-scopes")
    public JsonNode dataScopes() { return backend.get("permission-service", "/permissions/data-scopes"); }

    @PostMapping("/data-scopes")
    public JsonNode createDataScope(@RequestBody Object request) { return backend.post("permission-service", "/permissions/data-scopes", request); }

    @PutMapping("/roles/{roleId}/data-scopes")
    public JsonNode replaceRoleDataScopes(@PathVariable Long roleId, @RequestBody Object request) {
        return backend.put("permission-service", "/permissions/roles/" + roleId + "/data-scopes", request);
    }

    @GetMapping("/org-units")
    public JsonNode orgUnits() { return backend.get("permission-service", "/permissions/org-units"); }

    @PostMapping("/org-units")
    public JsonNode createOrgUnit(@RequestBody Object request) { return backend.post("permission-service", "/permissions/org-units", request); }

    @GetMapping("/audit/logs")
    public JsonNode auditLogs(@RequestParam(required = false) Long userId, @RequestParam(required = false) String eventType) {
        String path = "/audit/logs" + (userId == null && eventType == null ? "" : "?" + (userId == null ? "" : "userId=" + userId) + (userId != null && eventType != null ? "&" : "") + (eventType == null ? "" : "eventType=" + eventType));
        return backend.get("audit-service", path);
    }

    @GetMapping("/audit/dead-letters")
    public JsonNode deadLetters() { return backend.get("audit-service", "/audit/dead-letters"); }

    @PostMapping("/audit/dead-letters/{id}/replay")
    public JsonNode replayDeadLetter(@PathVariable Long id) { return backend.post("audit-service", "/audit/dead-letters/" + id + "/replay", null); }

    @DeleteMapping("/sessions/{userId}")
    public JsonNode revokeSessions(@PathVariable Long userId, @RequestHeader("X-User-Id") Long operatorId,
                                   @RequestHeader("X-Step-Up-Token") String stepUpToken) {
        return backend.deleteAsOperator("auth-service", "/auth/internal/users/" + userId + "/sessions", operatorId, stepUpToken);
    }

    @GetMapping("/outbox")
    public JsonNode outboxSummary() { return backend.get("permission-service", "/permissions/internal/outbox"); }

    @PostMapping("/outbox/{id}/retry")
    public JsonNode retryOutbox(@PathVariable Long id) {
        return backend.post("permission-service", "/permissions/internal/outbox/" + id + "/retry", null);
    }
}
