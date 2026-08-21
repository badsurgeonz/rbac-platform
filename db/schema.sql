CREATE DATABASE IF NOT EXISTS rbac DEFAULT CHARACTER SET utf8mb4;
USE rbac;
CREATE TABLE sys_user (id BIGINT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(64) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, status TINYINT NOT NULL DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE sys_role (id BIGINT PRIMARY KEY AUTO_INCREMENT, code VARCHAR(64) UNIQUE NOT NULL, name VARCHAR(64) NOT NULL, parent_id BIGINT NULL, status TINYINT NOT NULL DEFAULT 1);
CREATE TABLE sys_permission (id BIGINT PRIMARY KEY AUTO_INCREMENT, code VARCHAR(128) UNIQUE NOT NULL, name VARCHAR(128) NOT NULL, type VARCHAR(16) NOT NULL, resource VARCHAR(255), action VARCHAR(32), status TINYINT NOT NULL DEFAULT 1);
CREATE TABLE sys_user_role (user_id BIGINT NOT NULL, role_id BIGINT NOT NULL, PRIMARY KEY(user_id,role_id));
CREATE TABLE sys_role_permission (role_id BIGINT NOT NULL, permission_id BIGINT NOT NULL, PRIMARY KEY(role_id,permission_id));
CREATE TABLE sys_role_conflict (role_id BIGINT NOT NULL, conflict_role_id BIGINT NOT NULL, PRIMARY KEY(role_id,conflict_role_id));
CREATE TABLE sys_audit_log (id BIGINT PRIMARY KEY AUTO_INCREMENT, user_id BIGINT, event_type VARCHAR(32) NOT NULL, detail JSON, ip VARCHAR(64), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, INDEX idx_audit_user(user_id));
-- 示例账号：admin/password。生产环境必须替换为正式 BCrypt 哈希，并禁止使用默认密码。
INSERT INTO sys_user(username,password_hash) VALUES ('admin','$2a$10$bHWjn7VJUiG1jllN3N7eX.VK.i9MwtuM0ehDTKEOcyN1j0vs475E6');
INSERT INTO sys_role(code,name) VALUES ('SUPER_ADMIN','超级管理员'),('AUDITOR','审计员');
INSERT INTO sys_permission(code,name,type,resource,action) VALUES ('user:read','查看用户','API','/users/**','READ'),('permission:write','修改权限','API','/permissions/**','WRITE'),('audit:read','查看审计日志','API','/audit/**','READ');
INSERT INTO sys_user_role(user_id, role_id) SELECT u.id, r.id FROM sys_user u, sys_role r WHERE u.username = 'admin' AND r.code = 'SUPER_ADMIN';
INSERT INTO sys_role_permission(role_id, permission_id) SELECT r.id, p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.code = 'SUPER_ADMIN';
