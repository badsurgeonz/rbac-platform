package com.example.rbac.business;

import com.example.rbac.common.ApiResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@RestController
@RequestMapping("/business")
public class BusinessController {
    private final JdbcTemplate jdbc;
    private final DataScopePolicyClient policyClient;
    private final ExecutorService exportExecutor = Executors.newSingleThreadExecutor();
    private final Map<String, ExportJob> exportJobs = new ConcurrentHashMap<>();

    public BusinessController(JdbcTemplate jdbc, DataScopePolicyClient policyClient) { this.jdbc = jdbc; this.policyClient = policyClient; }

    @GetMapping("/documents")
    public ApiResponse<Page<DocumentView>> documents(@RequestHeader("X-User-Id") Long userId,
                                                     @RequestParam(defaultValue = "0") int page,
                                                     @RequestParam(defaultValue = "20") int size) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 200);
        DataScopeSql.Filter filter = DataScopeSql.filter(policyClient.policy(userId), userId);
        long total = jdbc.queryForObject("SELECT COUNT(*) FROM biz_document WHERE " + filter.predicate(), Long.class, filter.args().toArray());
        List<DocumentView> rows = jdbc.query("SELECT id, title, owner_user_id, org_unit_id, tenant_id, created_at FROM biz_document WHERE " + filter.predicate()
                        + " ORDER BY id DESC LIMIT ? OFFSET ?",
                (rs, rowNum) -> new DocumentView(rs.getLong("id"), rs.getString("title"), rs.getLong("owner_user_id"),
                        rs.getLong("org_unit_id"), rs.getString("tenant_id"), rs.getTimestamp("created_at").toInstant()),
                argsWith(filter, safeSize, (long) safePage * safeSize));
        return ApiResponse.ok(new Page<>(rows, total, safePage, safeSize));
    }

    @GetMapping("/documents/{id}")
    public ApiResponse<DocumentView> document(@RequestHeader("X-User-Id") Long userId, @PathVariable Long id) {
        DataScopeSql.Filter filter = DataScopeSql.filter(policyClient.policy(userId), userId);
        List<Object> args = new ArrayList<>(List.of(id));
        args.addAll(filter.args());
        List<DocumentView> rows = jdbc.query("SELECT id, title, owner_user_id, org_unit_id, tenant_id, created_at FROM biz_document WHERE id = ? AND " + filter.predicate(),
                (rs, rowNum) -> new DocumentView(rs.getLong("id"), rs.getString("title"), rs.getLong("owner_user_id"),
                        rs.getLong("org_unit_id"), rs.getString("tenant_id"), rs.getTimestamp("created_at").toInstant()),
                args.toArray());
        if (rows.isEmpty()) return ApiResponse.fail(404, "文档不存在或无权访问");
        return ApiResponse.ok(rows.get(0));
    }

    @PostMapping("/documents/batch")
    public ApiResponse<List<DocumentView>> batch(@RequestHeader("X-User-Id") Long userId, @RequestBody Set<Long> ids) {
        if (ids == null || ids.isEmpty()) return ApiResponse.ok(List.of());
        if (ids.size() > 200) throw new IllegalArgumentException("单次批量最多查询 200 条");
        DataScopeSql.Filter filter = DataScopeSql.filter(policyClient.policy(userId), userId);
        List<Long> idList = new ArrayList<>(ids);
        String placeholders = String.join(",", java.util.Collections.nCopies(idList.size(), "?"));
        List<Object> args = new ArrayList<>(idList);
        args.addAll(filter.args());
        List<DocumentView> rows = jdbc.query("SELECT id, title, owner_user_id, org_unit_id, tenant_id, created_at FROM biz_document WHERE id IN (" + placeholders + ") AND " + filter.predicate(),
                (rs, rowNum) -> new DocumentView(rs.getLong("id"), rs.getString("title"), rs.getLong("owner_user_id"),
                        rs.getLong("org_unit_id"), rs.getString("tenant_id"), rs.getTimestamp("created_at").toInstant()),
                args.toArray());
        return ApiResponse.ok(rows);
    }

    @GetMapping("/documents/export.csv")
    public String exportCsv(@RequestHeader("X-User-Id") Long userId) {
        DataScopeSql.Filter filter = DataScopeSql.filter(policyClient.policy(userId), userId);
        List<DocumentView> rows = jdbc.query("SELECT id, title, owner_user_id, org_unit_id, tenant_id, created_at FROM biz_document WHERE " + filter.predicate() + " ORDER BY id DESC LIMIT 10000",
                (rs, rowNum) -> new DocumentView(rs.getLong("id"), rs.getString("title"), rs.getLong("owner_user_id"),
                        rs.getLong("org_unit_id"), rs.getString("tenant_id"), rs.getTimestamp("created_at").toInstant()),
                filter.args().toArray());
        return toCsv(rows);
    }

    @PostMapping("/documents/export/async")
    public ApiResponse<Map<String, String>> exportAsync(@RequestHeader("X-User-Id") Long userId) {
        DataScopePolicyClient.Policy policy = policyClient.policy(userId);
        String jobId = UUID.randomUUID().toString();
        ExportJob job = new ExportJob(jobId, userId, policy, "RUNNING", null, null, Instant.now());
        exportJobs.put(jobId, job);
        exportExecutor.submit(() -> {
            try {
                DataScopeSql.Filter filter = DataScopeSql.filter(job.policy(), job.userId());
                List<DocumentView> rows = jdbc.query("SELECT id, title, owner_user_id, org_unit_id, tenant_id, created_at FROM biz_document WHERE " + filter.predicate() + " ORDER BY id DESC LIMIT 10000",
                        (rs, rowNum) -> new DocumentView(rs.getLong("id"), rs.getString("title"), rs.getLong("owner_user_id"),
                                rs.getLong("org_unit_id"), rs.getString("tenant_id"), rs.getTimestamp("created_at").toInstant()),
                        filter.args().toArray());
                job.complete(toCsv(rows));
            } catch (RuntimeException exception) {
                job.fail(exception.getMessage());
            }
        });
        return ApiResponse.ok(Map.of("jobId", jobId));
    }

    @GetMapping("/documents/export/jobs/{jobId}")
    public ApiResponse<ExportJobView> exportJob(@PathVariable String jobId) {
        ExportJob job = exportJobs.get(jobId);
        if (job == null) return ApiResponse.fail(404, "导出任务不存在");
        return ApiResponse.ok(new ExportJobView(job.status(), job.csv(), job.error(), job.createdAt()));
    }

    private Object[] argsWith(DataScopeSql.Filter filter, Object... extra) {
        List<Object> args = new ArrayList<>(filter.args());
        args.addAll(List.of(extra));
        return args.toArray();
    }

    private String toCsv(List<DocumentView> rows) {
        StringBuilder csv = new StringBuilder("id,title,owner_user_id,org_unit_id,tenant_id,created_at\n");
        for (DocumentView row : rows) {
            csv.append(row.id()).append(',').append(sanitizeCsv(row.title())).append(',').append(row.ownerUserId()).append(',')
                    .append(row.orgUnitId()).append(',').append(row.tenantId()).append(',').append(row.createdAt()).append('\n');
        }
        return csv.toString();
    }

    private String sanitizeCsv(String value) {
        if (value == null) return "";
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    public record Page<T>(List<T> items, long total, int page, int size) {}
    public record DocumentView(Long id, String title, Long ownerUserId, Long orgUnitId, String tenantId, Instant createdAt) {}
    public record ExportJobView(String status, String csv, String error, Instant createdAt) {}

    static final class ExportJob {
        private final String id;
        private final Long userId;
        private final DataScopePolicyClient.Policy policy;
        private volatile String status;
        private volatile String csv;
        private volatile String error;
        private final Instant createdAt;
        ExportJob(String id, Long userId, DataScopePolicyClient.Policy policy, String status, String csv, String error, Instant createdAt) {
            this.id = id; this.userId = userId; this.policy = policy; this.status = status; this.csv = csv; this.error = error; this.createdAt = createdAt;
        }
        void complete(String csv) { this.status = "COMPLETED"; this.csv = csv; }
        void fail(String error) { this.status = "FAILED"; this.error = error; }
        public String id() { return id; }
        Long userId() { return userId; }
        DataScopePolicyClient.Policy policy() { return policy; }
        String status() { return status; }
        String csv() { return csv; }
        String error() { return error; }
        Instant createdAt() { return createdAt; }
    }
}
