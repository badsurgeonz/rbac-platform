ALTER TABLE sys_outbox_event ADD COLUMN IF NOT EXISTS last_error VARCHAR(1000) NULL AFTER next_attempt_at;
CREATE TABLE IF NOT EXISTS sys_audit_log_archive (
    id BIGINT PRIMARY KEY,
    event_id CHAR(36) UNIQUE,
    user_id BIGINT,
    event_type VARCHAR(64) NOT NULL,
    detail JSON,
    ip VARCHAR(64),
    created_at TIMESTAMP NOT NULL,
    archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sys_audit_dead_letter (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    event_id CHAR(36) UNIQUE,
    routing_key VARCHAR(128),
    payload JSON NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    attempts INT NOT NULL DEFAULT 0,
    last_error VARCHAR(1000),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    replayed_at TIMESTAMP NULL
);
