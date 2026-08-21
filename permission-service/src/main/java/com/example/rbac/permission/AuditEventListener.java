package com.example.rbac.permission;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class AuditEventListener {
    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    public AuditEventListener(JdbcTemplate jdbc, ObjectMapper objectMapper) { this.jdbc = jdbc; this.objectMapper = objectMapper; }
    @RabbitListener(queues = PermissionMessagingConfiguration.AUDIT_QUEUE)
    public void consume(PermissionEvent event) throws JsonProcessingException {
        jdbc.update("INSERT INTO sys_audit_log(user_id, event_type, detail) VALUES (?, ?, ?)", event.userId(), "PERMISSION_CHANGED", objectMapper.writeValueAsString(event));
    }
}
