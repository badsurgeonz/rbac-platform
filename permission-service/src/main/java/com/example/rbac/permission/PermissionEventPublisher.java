package com.example.rbac.permission;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Component;

@Component
public class PermissionEventPublisher {
    private final RabbitTemplate rabbit;
    public PermissionEventPublisher(RabbitTemplate rabbit) { this.rabbit = rabbit; }
    public void publish(PermissionEvent event) { rabbit.convertAndSend(PermissionMessagingConfiguration.EXCHANGE, "permission.changed", event); }
}
