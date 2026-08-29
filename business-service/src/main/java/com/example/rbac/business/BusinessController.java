package com.example.rbac.business;

import com.example.rbac.common.ApiResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/business")
public class BusinessController {
    private final JdbcTemplate jdbc;
    private final DataScopePolicyClient policyClient;
    public BusinessController(JdbcTemplate jdbc, DataScopePolicyClient policyClient) { this.jdbc = jdbc; this.policyClient = policyClient; }

    @GetMapping("/documents")
    public ApiResponse<List<DocumentView>> documents(@RequestHeader("X-User-Id") Long userId) {
        DataScopePolicyClient.Policy policy = policyClient.policy(userId);
        StringBuilder sql = new StringBuilder("SELECT id, title, owner_user_id, org_unit_id, tenant_id, created_at FROM biz_document WHERE ");
        List<Object> args = new ArrayList<>();
        List<String> predicates = new ArrayList<>();
        if (policy.allAllowed()) predicates.add("1 = 1");
        if (policy.selfAllowed()) { predicates.add("owner_user_id = ?"); args.add(userId); }
        if (!policy.allowedOrgUnitIds().isEmpty()) {
            predicates.add("org_unit_id IN (" + "?,".repeat(policy.allowedOrgUnitIds().size()).replaceAll(",$", "") + ")");
            args.addAll(policy.allowedOrgUnitIds());
        }
        if (predicates.isEmpty()) sql.append("1 = 0"); else sql.append(String.join(" OR ", predicates));
        sql.append(" ORDER BY id DESC LIMIT 200");
        return ApiResponse.ok(jdbc.query(sql.toString(), (rs, rowNum) -> new DocumentView(rs.getLong("id"), rs.getString("title"), rs.getLong("owner_user_id"), rs.getLong("org_unit_id"), rs.getString("tenant_id"), rs.getTimestamp("created_at").toInstant()), args.toArray()));
    }
    public record DocumentView(Long id, String title, Long ownerUserId, Long orgUnitId, String tenantId, java.time.Instant createdAt) {}
}
