CREATE TABLE biz_document (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    owner_user_id BIGINT NOT NULL,
    org_unit_id BIGINT NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_biz_document_owner(owner_user_id),
    INDEX idx_biz_document_org(org_unit_id),
    INDEX idx_biz_document_tenant(tenant_id)
);
