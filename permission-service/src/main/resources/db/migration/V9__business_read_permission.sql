INSERT INTO sys_permission(code, name, type, resource, action)
VALUES ('business:read', '查看业务数据', 'API', '/business/**', 'READ')
ON DUPLICATE KEY UPDATE status = 1;
INSERT IGNORE INTO sys_role_permission(role_id, permission_id)
SELECT r.id, p.id FROM sys_role r CROSS JOIN sys_permission p
WHERE r.code = 'SUPER_ADMIN' AND p.code = 'business:read';
