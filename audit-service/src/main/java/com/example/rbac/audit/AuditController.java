package com.example.rbac.audit;

import com.example.rbac.common.ApiResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/audit")
public class AuditController {
    private final JdbcTemplate jdbc;
    private final RabbitTemplate rabbit;
    private final ObjectMapper objectMapper;

    public AuditController(JdbcTemplate jdbc, RabbitTemplate rabbit, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.rabbit = rabbit;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/logs")
    public ApiResponse<List<AuditLogView>> logs(@RequestParam(required = false) Long userId,
                                                @RequestParam(required = false) String eventType) {
        return ApiResponse.ok(jdbc.query("""
                SELECT id, event_id, user_id, event_type, detail, ip, created_at
                FROM sys_audit_log
                WHERE (? IS NULL OR user_id = ?) AND (? IS NULL OR event_type = ?)
                ORDER BY id DESC LIMIT 200
                """, (rs, rowNum) -> new AuditLogView(rs.getLong("id"), rs.getString("event_id"),
                        (Long) rs.getObject("user_id"), rs.getString("event_type"), rs.getString("detail"),
                        rs.getString("ip"), rs.getTimestamp("created_at").toInstant()), userId, userId, eventType, eventType));
    }

    @GetMapping("/dead-letters")
    public ApiResponse<List<DeadLetterView>> deadLetters() {
        return ApiResponse.ok(jdbc.query("SELECT id, event_id, routing_key, status, attempts, last_error, created_at, replayed_at FROM sys_audit_dead_letter ORDER BY id DESC LIMIT 200",
                (rs, rowNum) -> new DeadLetterView(rs.getLong("id"), rs.getString("event_id"), rs.getString("routing_key"), rs.getString("status"), rs.getInt("attempts"), rs.getString("last_error"), rs.getTimestamp("created_at").toInstant(), rs.getTimestamp("replayed_at") == null ? null : rs.getTimestamp("replayed_at").toInstant())));
    }

    @PostMapping("/dead-letters/{id}/replay")
    public ApiResponse<Void> replay(@org.springframework.web.bind.annotation.PathVariable Long id) throws Exception {
        var row = jdbc.queryForMap("SELECT routing_key, payload FROM sys_audit_dead_letter WHERE id = ? AND status = 'PENDING'", id);
        var event = objectMapper.readValue((String) row.get("payload"), com.example.rbac.common.PermissionEventContract.class);
        rabbit.convertAndSend(AuditMessagingConfiguration.EXCHANGE, String.valueOf(row.get("routing_key")), event);
        jdbc.update("UPDATE sys_audit_dead_letter SET status = 'REPLAYED', attempts = attempts + 1, replayed_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'PENDING'", id);
        return ApiResponse.ok(null);
    }

    public record AuditLogView(Long id, String eventId, Long userId, String eventType, String detail, String ip,
                               java.time.Instant createdAt) {}
    public record DeadLetterView(Long id, String eventId, String routingKey, String status, int attempts, String lastError,
                                 java.time.Instant createdAt, java.time.Instant replayedAt) {}
}
