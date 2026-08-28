INSERT INTO sys_permission(code, name, type, resource, action)
VALUES ('audit:write', '管理审计事件', 'API', '/audit/**', 'WRITE')
ON DUPLICATE KEY UPDATE status = 1;
INSERT IGNORE INTO sys_role_permission(role_id, permission_id)
SELECT r.id, p.id FROM sys_role r CROSS JOIN sys_permission p
WHERE r.code = 'SUPER_ADMIN' AND p.code = 'audit:write';
