package com.example.rbac.permission;

import com.example.rbac.common.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/permissions")
public class PermissionController {
    private final JdbcTemplate jdbc;

    public PermissionController(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @GetMapping("/users/{userId}")
    public ApiResponse<Set<String>> permissions(@PathVariable Long userId) {
        List<String> result = jdbc.queryForList("""
                WITH RECURSIVE role_tree AS (
                    SELECT r.id, r.parent_id FROM sys_role r JOIN sys_user_role ur ON ur.role_id = r.id WHERE ur.user_id = ?
                    UNION ALL
                    SELECT parent.id, parent.parent_id FROM sys_role parent JOIN role_tree child ON child.parent_id = parent.id
                )
                SELECT DISTINCT p.code FROM role_tree rt JOIN sys_role_permission rp ON rp.role_id = rt.id
                JOIN sys_permission p ON p.id = rp.permission_id WHERE p.status = 1
                """, String.class, userId);
        return ApiResponse.ok(Set.copyOf(result));
    }

    @GetMapping("/roles")
    public ApiResponse<List<RoleView>> roles() {
        return ApiResponse.ok(jdbc.query("SELECT id, code, name, parent_id FROM sys_role WHERE status = 1 ORDER BY id", (rs, rowNum) -> new RoleView(rs.getLong("id"), rs.getString("code"), rs.getString("name"), (Long) rs.getObject("parent_id"))));
    }

    @GetMapping
    public ApiResponse<List<PermissionView>> allPermissions() {
        return ApiResponse.ok(jdbc.query("SELECT id, code, name, type, resource, action FROM sys_permission WHERE status = 1 ORDER BY id", (rs, rowNum) -> new PermissionView(rs.getLong("id"), rs.getString("code"), rs.getString("name"), rs.getString("type"), rs.getString("resource"), rs.getString("action"))));
    }

    @PutMapping("/users/{userId}/roles")
    @Transactional
    public ApiResponse<Void> replaceUserRoles(@PathVariable Long userId, @RequestBody Set<Long> roleIds) {
        ensureUserExists(userId);
        validateRoleConflicts(roleIds);
        jdbc.update("DELETE FROM sys_user_role WHERE user_id = ?", userId);
        roleIds.forEach(roleId -> jdbc.update("INSERT INTO sys_user_role(user_id, role_id) VALUES (?, ?)", userId, roleId));
        return ApiResponse.ok(null);
    }

    @PutMapping("/roles/{roleId}/permissions")
    @Transactional
    public ApiResponse<Void> replaceRolePermissions(@PathVariable Long roleId, @RequestBody Set<Long> permissionIds) {
        ensureRoleExists(roleId);
        jdbc.update("DELETE FROM sys_role_permission WHERE role_id = ?", roleId);
        permissionIds.forEach(permissionId -> {
            if (jdbc.queryForObject("SELECT COUNT(*) FROM sys_permission WHERE id = ? AND status = 1", Integer.class, permissionId) == 0) {
                throw new IllegalArgumentException("权限不存在: " + permissionId);
            }
            jdbc.update("INSERT INTO sys_role_permission(role_id, permission_id) VALUES (?, ?)", roleId, permissionId);
        });
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
        for (Long roleId : roleIds) ensureRoleExists(roleId);
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
    private String placeholders(int count) { return String.join(",", java.util.Collections.nCopies(count, "?")); }
    private Object[] arguments(Set<Long> first, Set<Long> second) { return java.util.stream.Stream.concat(first.stream(), second.stream()).toArray(); }

    public record ParentRoleRequest(Long parentId) {}
    public record CreateRoleRequest(@NotBlank String code, @NotBlank String name) {}
    public record CreatePermissionRequest(@NotBlank String code, @NotBlank String name, @NotBlank String type, String resource, String action) {}
    public record RoleView(Long id, String code, String name, Long parentId) {}
    public record PermissionView(Long id, String code, String name, String type, String resource, String action) {}
}
