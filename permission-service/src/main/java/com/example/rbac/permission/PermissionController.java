package com.example.rbac.permission;

import com.example.rbac.common.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.HashSet;

@RestController
@RequestMapping("/permissions")
public class PermissionController {
    private final JdbcTemplate jdbc;
    private final StringRedisTemplate redis;
    private final PermissionEventPublisher eventPublisher;

    public PermissionController(JdbcTemplate jdbc, StringRedisTemplate redis, PermissionEventPublisher eventPublisher) {
        this.jdbc = jdbc;
        this.redis = redis;
        this.eventPublisher = eventPublisher;
    }

    @GetMapping("/users/{userId}")
    public ApiResponse<Set<String>> permissions(@PathVariable Long userId,
                                                @RequestHeader("X-User-Id") Long currentUserId,
                                                @RequestHeader(value = "X-User-Permissions", defaultValue = "") String currentPermissions) {
        if (!userId.equals(currentUserId) && !hasPermission(currentPermissions, "user:read")) {
            return ApiResponse.fail(403, "无权查询其他用户权限");
        }
        ensureUserExists(userId);
        return ApiResponse.ok(resolvePermissions(userId));
    }

    @GetMapping("/internal/users/{userId}/permissions")
    public ApiResponse<Set<String>> internalPermissions(@PathVariable Long userId) {
        ensureUserExists(userId);
        return ApiResponse.ok(resolvePermissions(userId));
    }

    @GetMapping("/internal/roles")
    public ApiResponse<List<RoleView>> internalRoles() {
        return roles();
    }

    @GetMapping("/internal/outbox")
    public ApiResponse<java.util.Map<String, Long>> outboxSummary() {
        return ApiResponse.ok(jdbc.query("SELECT status, COUNT(*) AS total FROM sys_outbox_event GROUP BY status",
                (rs, rowNum) -> java.util.Map.entry(rs.getString("status"), rs.getLong("total")))
                .stream().collect(java.util.stream.Collectors.toMap(java.util.Map.Entry::getKey, java.util.Map.Entry::getValue)));
    }

    @PostMapping("/internal/outbox/{id}/retry")
    public ApiResponse<Void> retryOutbox(@PathVariable Long id) {
        if (jdbc.update("UPDATE sys_outbox_event SET status = 'PENDING', next_attempt_at = CURRENT_TIMESTAMP, last_error = NULL WHERE id = ? AND status = 'DEAD'", id) == 0) {
            throw new IllegalArgumentException("不存在可重试的 Outbox 事件");
        }
        return ApiResponse.ok(null);
    }

    private Set<String> resolvePermissions(Long userId) {
        String key = cacheKey(userId, permissionVersion(userId));
        String cached = redis.opsForValue().get(key);
        if (cached != null) return cached.isBlank() ? Set.of() : Set.of(cached.split(","));
        List<String> result = jdbc.queryForList("""
                WITH RECURSIVE role_tree AS (
                    SELECT r.id, r.parent_id FROM sys_role r JOIN sys_user_role ur ON ur.role_id = r.id WHERE ur.user_id = ?
                    UNION ALL
                    SELECT parent.id, parent.parent_id FROM sys_role parent JOIN role_tree child ON child.parent_id = parent.id
                )
                SELECT DISTINCT p.code FROM role_tree rt JOIN sys_role_permission rp ON rp.role_id = rt.id
                JOIN sys_permission p ON p.id = rp.permission_id WHERE p.status = 1
                """, String.class, userId);
        Set<String> permissions = Set.copyOf(result);
        redis.opsForValue().set(key, String.join(",", permissions), Duration.ofMinutes(10));
        return permissions;
    }

    @GetMapping("/users/{userId}/data-scopes")
    public ApiResponse<List<DataScopeView>> dataScopes(@PathVariable Long userId) {
        ensureUserExists(userId);
        return ApiResponse.ok(jdbc.query("""
                WITH RECURSIVE role_tree AS (
                    SELECT r.id FROM sys_role r JOIN sys_user_role ur ON ur.role_id = r.id WHERE ur.user_id = ?
                    UNION ALL
                    SELECT parent.id FROM sys_role parent JOIN role_tree child ON child.id = parent.parent_id
                )
                SELECT DISTINCT ds.id, ds.code, ds.name, ds.scope_type, ds.org_unit_id, ds.condition_expr
                FROM sys_data_scope ds
                LEFT JOIN sys_role_data_scope rds ON rds.data_scope_id = ds.id
                LEFT JOIN sys_user_data_scope uds ON uds.data_scope_id = ds.id
                WHERE ds.status = 1 AND (rds.role_id IN (SELECT id FROM role_tree) OR uds.user_id = ?)
                ORDER BY ds.id
                """, (rs, rowNum) -> new DataScopeView(rs.getLong("id"), rs.getString("code"), rs.getString("name"),
                        rs.getString("scope_type"), (Long) rs.getObject("org_unit_id"), rs.getString("condition_expr")), userId, userId));
    }

    @PostMapping("/data-scopes")
    public ApiResponse<Long> createDataScope(@Valid @RequestBody CreateDataScopeRequest request) {
        jdbc.update("INSERT INTO sys_data_scope(code, name, scope_type, org_unit_id, condition_expr) VALUES (?, ?, ?, ?, ?)",
                request.code(), request.name(), request.scopeType(), request.orgUnitId(), request.conditionExpr());
        return ApiResponse.ok(jdbc.queryForObject("SELECT id FROM sys_data_scope WHERE code = ?", Long.class, request.code()));
    }

    @GetMapping("/data-scopes")
    public ApiResponse<List<DataScopeView>> allDataScopes() {
        return ApiResponse.ok(jdbc.query("SELECT id, code, name, scope_type, org_unit_id, condition_expr FROM sys_data_scope WHERE status = 1 ORDER BY id",
                (rs, rowNum) -> new DataScopeView(rs.getLong("id"), rs.getString("code"), rs.getString("name"),
                        rs.getString("scope_type"), (Long) rs.getObject("org_unit_id"), rs.getString("condition_expr"))));
    }

    @PutMapping("/users/{userId}/data-scopes")
    @Transactional
    public ApiResponse<Void> replaceUserDataScopes(@PathVariable Long userId, @RequestBody Set<Long> dataScopeIds) {
        ensureUserExists(userId);
        dataScopeIds.forEach(id -> {
            if (jdbc.queryForObject("SELECT COUNT(*) FROM sys_data_scope WHERE id = ? AND status = 1", Integer.class, id) == 0) {
                throw new IllegalArgumentException("数据权限不存在: " + id);
            }
        });
        jdbc.update("DELETE FROM sys_user_data_scope WHERE user_id = ?", userId);
        dataScopeIds.forEach(id -> jdbc.update("INSERT INTO sys_user_data_scope(user_id, data_scope_id) VALUES (?, ?)", userId, id));
        evictUser(userId);
        eventPublisher.publish(new PermissionEvent(userId, "USER_DATA_SCOPES_REPLACED", "USER", userId));
        return ApiResponse.ok(null);
    }

    @PostMapping("/data-scope/check")
    public ApiResponse<DataScopeDecision> checkDataScope(@RequestHeader("X-User-Id") Long currentUserId,
                                                         @RequestBody DataScopeCheckRequest request) {
        boolean allowed = jdbc.query("""
                WITH RECURSIVE role_tree AS (
                    SELECT r.id, r.parent_id FROM sys_role r JOIN sys_user_role ur ON ur.role_id = r.id WHERE ur.user_id = ?
                    UNION ALL
                    SELECT parent.id, parent.parent_id FROM sys_role parent JOIN role_tree child ON child.parent_id = parent.id
                )
                SELECT DISTINCT ds.scope_type, ds.org_unit_id
                FROM sys_data_scope ds
                LEFT JOIN sys_user_data_scope uds ON uds.data_scope_id = ds.id AND uds.user_id = ?
                LEFT JOIN sys_role_data_scope rds ON rds.data_scope_id = ds.id
                WHERE ds.status = 1 AND (uds.user_id IS NOT NULL OR rds.role_id IN (SELECT id FROM role_tree))
                """, (rs, rowNum) -> new ScopeRule(rs.getString("scope_type"), (Long) rs.getObject("org_unit_id")), currentUserId, currentUserId)
                .stream().anyMatch(rule -> matches(rule, currentUserId, request));
        return ApiResponse.ok(new DataScopeDecision(allowed, currentUserId, request.resource(), request.action()));
    }

    @GetMapping("/internal/users/{userId}/data-scope-policy")
    public ApiResponse<DataScopePolicy> dataScopePolicy(@PathVariable Long userId) {
        ensureUserExists(userId);
        boolean allAllowed = false;
        boolean selfAllowed = false;
        Set<Long> orgUnitIds = new HashSet<>();
        List<ScopeRule> rules = jdbc.query("""
                WITH RECURSIVE role_tree AS (
                    SELECT r.id, r.parent_id FROM sys_role r JOIN sys_user_role ur ON ur.role_id = r.id WHERE ur.user_id = ?
                    UNION ALL
                    SELECT parent.id, parent.parent_id FROM sys_role parent JOIN role_tree child ON child.parent_id = parent.id
                )
                SELECT DISTINCT ds.scope_type, ds.org_unit_id
                FROM sys_data_scope ds
                LEFT JOIN sys_user_data_scope uds ON uds.data_scope_id = ds.id AND uds.user_id = ?
                LEFT JOIN sys_role_data_scope rds ON rds.data_scope_id = ds.id
                WHERE ds.status = 1 AND (uds.user_id IS NOT NULL OR rds.role_id IN (SELECT id FROM role_tree))
                """, (rs, rowNum) -> new ScopeRule(rs.getString("scope_type"), (Long) rs.getObject("org_unit_id")), userId, userId);
        for (ScopeRule rule : rules) {
            DataScopeType type = DataScopeType.parse(rule.scopeType());
            if (type == DataScopeType.ALL) allAllowed = true;
            if (type == DataScopeType.SELF) selfAllowed = true;
            if ((type == DataScopeType.DEPARTMENT || type == DataScopeType.DEPARTMENT_AND_DESCENDANTS)
                    && rule.orgUnitId() != null && userBelongsToOrg(userId, rule.orgUnitId())) {
                if (type == DataScopeType.DEPARTMENT) orgUnitIds.add(rule.orgUnitId());
                else orgUnitIds.addAll(descendantOrgUnits(rule.orgUnitId()));
            }
        }
        return ApiResponse.ok(new DataScopePolicy(allAllowed, selfAllowed, orgUnitIds));
    }

    @PostMapping("/org-units")
    public ApiResponse<Long> createOrgUnit(@Valid @RequestBody CreateOrgUnitRequest request) {
        if (request.parentId() != null) ensureOrgUnitExists(request.parentId());
        jdbc.update("INSERT INTO sys_org_unit(code, name, parent_id) VALUES (?, ?, ?)", request.code(), request.name(), request.parentId());
        return ApiResponse.ok(jdbc.queryForObject("SELECT id FROM sys_org_unit WHERE code = ?", Long.class, request.code()));
    }

    @GetMapping("/org-units")
    public ApiResponse<List<OrgUnitView>> allOrgUnits() {
        return ApiResponse.ok(jdbc.query("SELECT id, code, name, parent_id, status FROM sys_org_unit WHERE status = 1 ORDER BY id",
                (rs, rowNum) -> new OrgUnitView(rs.getLong("id"), rs.getString("code"), rs.getString("name"),
                        (Long) rs.getObject("parent_id"), rs.getInt("status"))));
    }

    @PutMapping("/users/{userId}/org-units")
    @Transactional
    public ApiResponse<Void> replaceUserOrgUnits(@PathVariable Long userId, @RequestBody Set<Long> orgUnitIds) {
        ensureUserExists(userId);
        orgUnitIds.forEach(this::ensureOrgUnitExists);
        jdbc.update("DELETE FROM sys_user_org WHERE user_id = ?", userId);
        orgUnitIds.forEach(orgId -> jdbc.update("INSERT INTO sys_user_org(user_id, org_unit_id) VALUES (?, ?)", userId, orgId));
        return ApiResponse.ok(null);
    }

    @GetMapping("/roles")
    public ApiResponse<List<RoleView>> roles() {
        return ApiResponse.ok(jdbc.query("SELECT id, code, name, parent_id FROM sys_role WHERE status = 1 ORDER BY id",
                (rs, rowNum) -> new RoleView(rs.getLong("id"), rs.getString("code"), rs.getString("name"), (Long) rs.getObject("parent_id"))));
    }

    @GetMapping
    public ApiResponse<List<PermissionView>> allPermissions() {
        return ApiResponse.ok(jdbc.query("SELECT id, code, name, type, resource, action FROM sys_permission WHERE status = 1 ORDER BY id",
                (rs, rowNum) -> new PermissionView(rs.getLong("id"), rs.getString("code"), rs.getString("name"), rs.getString("type"), rs.getString("resource"), rs.getString("action"))));
    }

    @PutMapping("/users/{userId}/roles")
    @Transactional
    public ApiResponse<Void> replaceUserRoles(@PathVariable Long userId, @RequestBody Set<Long> roleIds) {
        ensureUserExists(userId);
        validateRoleConflicts(roleIds);
        jdbc.update("DELETE FROM sys_user_role WHERE user_id = ?", userId);
        roleIds.forEach(roleId -> jdbc.update("INSERT INTO sys_user_role(user_id, role_id) VALUES (?, ?)", userId, roleId));
        evictUser(userId);
        eventPublisher.publish(new PermissionEvent(userId, "USER_ROLES_REPLACED", "USER", userId));
        return ApiResponse.ok(null);
    }

    @PutMapping("/roles/{roleId}/permissions")
    @Transactional
    public ApiResponse<Void> replaceRolePermissions(@PathVariable Long roleId, @RequestBody Set<Long> permissionIds) {
        ensureRoleExists(roleId);
        permissionIds.forEach(permissionId -> {
            if (jdbc.queryForObject("SELECT COUNT(*) FROM sys_permission WHERE id = ? AND status = 1", Integer.class, permissionId) == 0) {
                throw new IllegalArgumentException("权限不存在: " + permissionId);
            }
        });
        jdbc.update("DELETE FROM sys_role_permission WHERE role_id = ?", roleId);
        permissionIds.forEach(permissionId -> jdbc.update("INSERT INTO sys_role_permission(role_id, permission_id) VALUES (?, ?)", roleId, permissionId));
        publishRoleChange(roleId, "ROLE_PERMISSIONS_REPLACED");
        return ApiResponse.ok(null);
    }

    @PutMapping("/roles/{roleId}/data-scopes")
    @Transactional
    public ApiResponse<Void> replaceRoleDataScopes(@PathVariable Long roleId, @RequestBody Set<Long> dataScopeIds) {
        ensureRoleExists(roleId);
        dataScopeIds.forEach(id -> {
            if (jdbc.queryForObject("SELECT COUNT(*) FROM sys_data_scope WHERE id = ? AND status = 1", Integer.class, id) == 0) {
                throw new IllegalArgumentException("数据权限不存在: " + id);
            }
        });
        jdbc.update("DELETE FROM sys_role_data_scope WHERE role_id = ?", roleId);
        dataScopeIds.forEach(id -> jdbc.update("INSERT INTO sys_role_data_scope(role_id, data_scope_id) VALUES (?, ?)", roleId, id));
        evictAffectedRoleUsers(roleId);
        eventPublisher.publish(new PermissionEvent(null, "ROLE_DATA_SCOPES_REPLACED", "ROLE", roleId));
        return ApiResponse.ok(null);
    }

    @PutMapping("/roles/{roleId}/conflicts")
    @Transactional
    public ApiResponse<Void> replaceRoleConflicts(@PathVariable Long roleId, @RequestBody Set<Long> conflictRoleIds) {
        ensureRoleExists(roleId);
        if (conflictRoleIds.contains(roleId)) throw new IllegalArgumentException("角色不能与自身冲突");
        conflictRoleIds.forEach(this::ensureRoleExists);
        jdbc.update("DELETE FROM sys_role_conflict WHERE role_id = ?", roleId);
        conflictRoleIds.forEach(conflictId -> jdbc.update("INSERT INTO sys_role_conflict(role_id, conflict_role_id) VALUES (?, ?)", roleId, conflictId));
        eventPublisher.publish(new PermissionEvent(null, "ROLE_CONFLICTS_REPLACED", "ROLE", roleId));
        return ApiResponse.ok(null);
    }

    @PutMapping("/roles/{roleId}/parent")
    @Transactional
    public ApiResponse<Void> setParent(@PathVariable Long roleId, @RequestBody ParentRoleRequest request) {
        ensureRoleExists(roleId);
        if (request.parentId() != null) {
            ensureRoleExists(request.parentId());
            if (roleId.equals(request.parentId()) || reaches(request.parentId(), roleId)) throw new IllegalArgumentException("角色继承关系会形成环");
        }
        jdbc.update("UPDATE sys_role SET parent_id = ? WHERE id = ?", request.parentId(), roleId);
        publishRoleChange(roleId, "ROLE_PARENT_CHANGED");
        return ApiResponse.ok(null);
    }

    @PostMapping("/roles")
    public ApiResponse<Long> createRole(@Valid @RequestBody CreateRoleRequest request) {
        jdbc.update("INSERT INTO sys_role(code, name) VALUES (?, ?)", request.code(), request.name());
        return ApiResponse.ok(jdbc.queryForObject("SELECT id FROM sys_role WHERE code = ?", Long.class, request.code()));
    }

    @PostMapping
    public ApiResponse<Long> createPermission(@Valid @RequestBody CreatePermissionRequest request) {
        jdbc.update("INSERT INTO sys_permission(code, name, type, resource, action) VALUES (?, ?, ?, ?, ?)", request.code(), request.name(), request.type(), request.resource(), request.action());
        return ApiResponse.ok(jdbc.queryForObject("SELECT id FROM sys_permission WHERE code = ?", Long.class, request.code()));
    }

    private void validateRoleConflicts(Set<Long> roleIds) {
        if (roleIds.isEmpty()) return;
        int count = jdbc.queryForObject("SELECT COUNT(*) FROM sys_role_conflict WHERE role_id IN (" + placeholders(roleIds.size()) + ") AND conflict_role_id IN (" + placeholders(roleIds.size()) + ")", Integer.class, arguments(roleIds, roleIds));
        if (count > 0) throw new IllegalArgumentException("角色之间存在职责冲突");
        roleIds.forEach(this::ensureRoleExists);
    }

    private boolean reaches(Long start, Long target) {
        Integer count = jdbc.queryForObject("""
                WITH RECURSIVE role_tree AS (SELECT id, parent_id FROM sys_role WHERE id = ? UNION ALL SELECT r.id, r.parent_id FROM sys_role r JOIN role_tree t ON r.id = t.parent_id)
                SELECT COUNT(*) FROM role_tree WHERE id = ?
                """, Integer.class, start, target);
        return count != null && count > 0;
    }

    private void ensureUserExists(Long id) { if (jdbc.queryForObject("SELECT COUNT(*) FROM sys_user WHERE id = ?", Integer.class, id) == 0) throw new IllegalArgumentException("用户不存在: " + id); }
    private void ensureRoleExists(Long id) { if (jdbc.queryForObject("SELECT COUNT(*) FROM sys_role WHERE id = ? AND status = 1", Integer.class, id) == 0) throw new IllegalArgumentException("角色不存在: " + id); }
    private void evictUser(Long userId) {
        redis.opsForValue().increment(versionKey(userId));
        redis.delete("rbac:permission:user:" + userId);
    }
    private void publishRoleChange(Long roleId, String action) {
        evictAffectedRoleUsers(roleId);
        eventPublisher.publish(new PermissionEvent(null, action, "ROLE", roleId));
    }
    private void evictAffectedRoleUsers(Long roleId) {
        jdbc.queryForList("""
                WITH RECURSIVE role_tree AS (
                    SELECT id FROM sys_role WHERE id = ?
                    UNION ALL
                    SELECT child.id FROM sys_role child JOIN role_tree parent ON child.parent_id = parent.id
                )
                SELECT DISTINCT ur.user_id FROM sys_user_role ur JOIN role_tree rt ON rt.id = ur.role_id
                """, Long.class, roleId).forEach(this::evictUser);
    }
    private long permissionVersion(Long userId) {
        String version = redis.opsForValue().get(versionKey(userId));
        return version == null ? 1L : Long.parseLong(version);
    }
    private String versionKey(Long userId) { return "rbac:permission:version:" + userId; }
    private String cacheKey(Long userId, long version) { return "rbac:permission:user:" + userId + ":v" + version; }
    private String placeholders(int count) { return String.join(",", java.util.Collections.nCopies(count, "?")); }
    private Object[] arguments(Set<Long> first, Set<Long> second) { return java.util.stream.Stream.concat(first.stream(), second.stream()).toArray(); }
    private boolean hasPermission(String permissions, String required) {
        return Set.of(permissions.split(",")).contains(required);
    }
    private boolean matches(ScopeRule rule, Long currentUserId, DataScopeCheckRequest request) {
        DataScopeType type = DataScopeType.parse(rule.scopeType());
        if (type == DataScopeType.ALL) return true;
        if (type == DataScopeType.SELF) return request.ownerUserId() != null && currentUserId.equals(request.ownerUserId());
        if (type == DataScopeType.DEPARTMENT) return rule.orgUnitId() != null && request.orgUnitId() != null
                && userBelongsToOrg(currentUserId, rule.orgUnitId()) && rule.orgUnitId().equals(request.orgUnitId());
        if (type == DataScopeType.DEPARTMENT_AND_DESCENDANTS) return rule.orgUnitId() != null && request.orgUnitId() != null
                && userBelongsToOrg(currentUserId, rule.orgUnitId()) && isOrgDescendant(request.orgUnitId(), rule.orgUnitId());
        return false;
    }
    private boolean userBelongsToOrg(Long userId, Long orgUnitId) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM sys_user_org WHERE user_id = ? AND org_unit_id = ?", Integer.class, userId, orgUnitId) > 0;
    }
    private boolean isOrgDescendant(Long candidate, Long ancestor) {
        Integer count = jdbc.queryForObject("""
                WITH RECURSIVE org_tree AS (SELECT id, parent_id FROM sys_org_unit WHERE id = ?
                    UNION ALL SELECT child.id, child.parent_id FROM sys_org_unit child JOIN org_tree parent ON child.parent_id = parent.id)
                SELECT COUNT(*) FROM org_tree WHERE id = ?
                """, Integer.class, ancestor, candidate);
        return count != null && count > 0;
    }
    private Set<Long> descendantOrgUnits(Long ancestor) {
        return new HashSet<>(jdbc.queryForList("""
                WITH RECURSIVE org_tree AS (SELECT id, parent_id FROM sys_org_unit WHERE id = ?
                    UNION ALL SELECT child.id, child.parent_id FROM sys_org_unit child JOIN org_tree parent ON child.parent_id = parent.id)
                SELECT id FROM org_tree
                """, Long.class, ancestor));
    }
    private void ensureOrgUnitExists(Long id) {
        if (jdbc.queryForObject("SELECT COUNT(*) FROM sys_org_unit WHERE id = ? AND status = 1", Integer.class, id) == 0) {
            throw new IllegalArgumentException("组织节点不存在: " + id);
        }
    }

    public record ParentRoleRequest(Long parentId) {}
    public record CreateRoleRequest(@NotBlank String code, @NotBlank String name) {}
    public record CreatePermissionRequest(@NotBlank String code, @NotBlank String name, @NotBlank String type, String resource, String action) {}
    public record RoleView(Long id, String code, String name, Long parentId) {}
    public record PermissionView(Long id, String code, String name, String type, String resource, String action) {}
    public record DataScopeView(Long id, String code, String name, String scopeType, Long orgUnitId, String conditionExpr) {}
    public record CreateDataScopeRequest(@NotBlank String code, @NotBlank String name, @NotBlank String scopeType,
                                         Long orgUnitId, String conditionExpr) {}
    public record CreateOrgUnitRequest(@NotBlank String code, @NotBlank String name, Long parentId) {}
    public record OrgUnitView(Long id, String code, String name, Long parentId, int status) {}
    public record DataScopeCheckRequest(@NotBlank String resource, @NotBlank String action, Long ownerUserId, Long orgUnitId) {}
    public record DataScopeDecision(boolean allowed, Long userId, String resource, String action) {}
    public record DataScopePolicy(boolean allAllowed, boolean selfAllowed, Set<Long> allowedOrgUnitIds) {}
    private record ScopeRule(String scopeType, Long orgUnitId) {}
}
