INSERT INTO sys_permission(code, name, type, resource, action)
VALUES ('admin:read', '查看管理端', 'API', '/admin/**', 'READ'),
       ('admin:write', '修改管理端', 'API', '/admin/**', 'WRITE')
ON DUPLICATE KEY UPDATE status = 1;
INSERT IGNORE INTO sys_role_permission(role_id, permission_id)
SELECT r.id, p.id FROM sys_role r CROSS JOIN sys_permission p
WHERE r.code = 'SUPER_ADMIN' AND p.code IN ('admin:read', 'admin:write');
