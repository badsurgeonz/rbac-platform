package com.example.rbac.audit;

import com.example.rbac.common.PermissionEventContract;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.core.Message;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class AuditEventListener {
    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public AuditEventListener(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    @RabbitListener(queues = AuditMessagingConfiguration.AUDIT_QUEUE)
    public void consume(PermissionEventContract event) throws JsonProcessingException {
        jdbc.update("INSERT INTO sys_audit_log(event_id, user_id, event_type, detail) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE event_id = event_id",
                event.eventId().toString(), event.userId(), event.eventType(), objectMapper.writeValueAsString(event));
    }

    @RabbitListener(queues = AuditMessagingConfiguration.DEAD_LETTER_QUEUE)
    public void consumeDeadLetter(Message message) throws Exception {
        var tree = objectMapper.readTree(message.getBody());
        String eventId = tree.path("eventId").asText(null);
        if (eventId == null) eventId = java.util.UUID.randomUUID().toString();
        String routingKey = message.getMessageProperties().getReceivedRoutingKey();
        jdbc.update("INSERT INTO sys_audit_dead_letter(event_id, routing_key, payload, last_error) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE event_id = event_id",
                eventId, routingKey, objectMapper.writeValueAsString(tree), "consumer delivery failed");
    }
}
