package com.example.rbac.permission;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import com.example.rbac.common.PermissionEventContract;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Value;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.springframework.amqp.rabbit.connection.CorrelationData;

@Component
public class PermissionEventPublisher {
    private final RabbitTemplate rabbit;
    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final int maxAttempts;

    public PermissionEventPublisher(RabbitTemplate rabbit, JdbcTemplate jdbc, ObjectMapper objectMapper,
                                    @Value("${messaging.outbox.max-attempts:12}") int maxAttempts) {
        this.rabbit = rabbit;
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.maxAttempts = maxAttempts;
    }

    @Transactional
    public void publish(PermissionEvent event) {
        PermissionEventContract contract = PermissionEventContract.create(
                event.action(), event.userId(), null, event.subjectType(), event.subjectId(), null, Map.of());
        try {
            jdbc.update("INSERT INTO sys_outbox_event(event_id, event_type, routing_key, payload, next_attempt_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    contract.eventId().toString(), contract.eventType(), "permission.changed", objectMapper.writeValueAsString(contract));
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Unable to serialize permission event", exception);
        }
    }

    @Scheduled(fixedDelayString = "${messaging.outbox.poll-interval-ms:1000}")
    public void publishPending() {
        jdbc.update("UPDATE sys_outbox_event SET status = 'PENDING', next_attempt_at = CURRENT_TIMESTAMP WHERE status = 'PUBLISHING' AND updated_at < DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 MINUTE)");
        jdbc.update("UPDATE sys_outbox_event SET status = 'DEAD', last_error = COALESCE(last_error, 'maximum publish attempts exceeded') WHERE status = 'PENDING' AND attempts >= ?", maxAttempts);
        List<OutboxRow> rows = jdbc.query("SELECT id, event_id, event_type, routing_key, payload FROM sys_outbox_event WHERE status = 'PENDING' AND (next_attempt_at IS NULL OR next_attempt_at <= CURRENT_TIMESTAMP) ORDER BY id LIMIT 20",
                (rs, rowNum) -> new OutboxRow(rs.getLong("id"), rs.getString("event_id"), rs.getString("event_type"), rs.getString("routing_key"), rs.getString("payload")));
        rows.forEach(this::send);
    }

    private void send(OutboxRow row) {
        if (jdbc.update("UPDATE sys_outbox_event SET status = 'PUBLISHING', attempts = attempts + 1 WHERE id = ? AND status = 'PENDING'", row.id()) == 0) return;
        try {
            var event = objectMapper.readValue(row.payload(), PermissionEventContract.class);
            CorrelationData correlation = new CorrelationData(row.eventId());
            rabbit.convertAndSend(PermissionMessagingConfiguration.EXCHANGE, row.routingKey(), event, correlation);
            var confirm = correlation.getFuture().get(5, TimeUnit.SECONDS);
            if (!confirm.isAck()) throw new IllegalStateException("RabbitMQ rejected event: " + confirm.getReason());
            jdbc.update("UPDATE sys_outbox_event SET status = 'PUBLISHED', published_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'PUBLISHING'", row.id());
        } catch (Exception exception) {
            jdbc.update("UPDATE sys_outbox_event SET status = CASE WHEN attempts >= ? THEN 'DEAD' ELSE 'PENDING' END, last_error = ?, next_attempt_at = DATE_ADD(CURRENT_TIMESTAMP, INTERVAL LEAST(attempts * 5, 300) SECOND) WHERE id = ?", maxAttempts, exception.getMessage(), row.id());
        }
    }

    private record OutboxRow(Long id, String eventId, String eventType, String routingKey, String payload) {}
}
