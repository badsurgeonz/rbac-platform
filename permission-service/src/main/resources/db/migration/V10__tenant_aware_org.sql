ALTER TABLE sys_org_unit ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) NULL;

-- 示例组织树：两个租户，便于跨租户/跨部门验证
INSERT INTO sys_org_unit(id, code, name, parent_id, tenant_id) VALUES
 (1, 'HQ', '总部', NULL, 'TENANT_0001'),
 (2, 'RND', '研发部', 1, 'TENANT_0001'),
 (3, 'SALES', '销售部', 1, 'TENANT_0001'),
 (4, 'BR2', '分公司二', NULL, 'TENANT_0002')
ON DUPLICATE KEY UPDATE name = VALUES(name), parent_id = VALUES(parent_id), tenant_id = VALUES(tenant_id);

INSERT IGNORE INTO sys_user_org(user_id, org_unit_id)
SELECT u.id, 1 FROM sys_user u WHERE u.username = 'admin';

-- 示例数据范围：全部、本人、研发部门、总部及下属
INSERT INTO sys_data_scope(id, code, name, scope_type, org_unit_id, condition_expr) VALUES
 (1, 'ALL_DATA', '全部数据', 'ALL', NULL, NULL),
 (2, 'SELF_DATA', '本人数据', 'SELF', NULL, NULL),
 (3, 'DEPT_RND', '研发部', 'DEPARTMENT', 2, NULL),
 (4, 'TREE_HQ', '总部及下属', 'DEPARTMENT_AND_DESCENDANTS', 1, NULL)
ON DUPLICATE KEY UPDATE name = VALUES(name), scope_type = VALUES(scope_type), org_unit_id = VALUES(org_unit_id);

INSERT IGNORE INTO sys_role_data_scope(role_id, data_scope_id)
SELECT r.id, 1 FROM sys_role r WHERE r.code = 'SUPER_ADMIN';
