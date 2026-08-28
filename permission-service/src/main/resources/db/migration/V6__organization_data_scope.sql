CREATE TABLE IF NOT EXISTS sys_org_unit (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    code VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    parent_id BIGINT NULL,
    status TINYINT NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS sys_user_org (
    user_id BIGINT NOT NULL,
    org_unit_id BIGINT NOT NULL,
    PRIMARY KEY(user_id, org_unit_id)
);
