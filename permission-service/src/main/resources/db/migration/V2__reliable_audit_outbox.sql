ALTER TABLE sys_audit_log ADD COLUMN IF NOT EXISTS event_id CHAR(36) UNIQUE AFTER id;
ALTER TABLE sys_audit_log MODIFY event_type VARCHAR(64) NOT NULL;
CREATE TABLE IF NOT EXISTS sys_outbox_event (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    event_id CHAR(36) UNIQUE NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    routing_key VARCHAR(128) NOT NULL,
    payload JSON NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMP NULL,
    published_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_outbox_pending(status, next_attempt_at)
);
