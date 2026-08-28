CREATE TABLE IF NOT EXISTS sys_data_scope (id BIGINT PRIMARY KEY AUTO_INCREMENT, code VARCHAR(64) UNIQUE NOT NULL, name VARCHAR(128) NOT NULL, scope_type VARCHAR(32) NOT NULL, org_unit_id BIGINT NULL, condition_expr VARCHAR(1000) NULL, status TINYINT NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS sys_role_data_scope (role_id BIGINT NOT NULL, data_scope_id BIGINT NOT NULL, PRIMARY KEY(role_id, data_scope_id));
CREATE TABLE IF NOT EXISTS sys_user_data_scope (user_id BIGINT NOT NULL, data_scope_id BIGINT NOT NULL, PRIMARY KEY(user_id, data_scope_id));
