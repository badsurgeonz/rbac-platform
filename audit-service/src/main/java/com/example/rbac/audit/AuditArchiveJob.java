package com.example.rbac.audit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
public class AuditArchiveJob {
    private final JdbcTemplate jdbc;
    private final int retentionDays;

    public AuditArchiveJob(JdbcTemplate jdbc, @Value("${audit.archive.retention-days:365}") int retentionDays) {
        this.jdbc = jdbc;
        this.retentionDays = retentionDays;
    }

    @Scheduled(cron = "${audit.archive.cron:0 30 2 * * *}")
    @Transactional
    public void archiveBatch() {
        List<Long> ids = jdbc.queryForList("SELECT id FROM sys_audit_log WHERE created_at < DATE_SUB(CURRENT_TIMESTAMP, INTERVAL ? DAY) ORDER BY id LIMIT 500", Long.class, retentionDays);
        for (Long id : ids) {
            jdbc.update("INSERT IGNORE INTO sys_audit_log_archive(id, event_id, user_id, event_type, detail, ip, created_at) SELECT id, event_id, user_id, event_type, detail, ip, created_at FROM sys_audit_log WHERE id = ?", id);
            jdbc.update("DELETE FROM sys_audit_log WHERE id = ? AND EXISTS (SELECT 1 FROM sys_audit_log_archive WHERE id = ?)", id, id);
        }
    }
}
