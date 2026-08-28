package com.example.rbac.permission;

import org.springframework.amqp.core.TopicExchange;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
public class PermissionMessagingConfiguration {
    public static final String EXCHANGE = "rbac.events";
    @Bean TopicExchange rbacExchange() { return new TopicExchange(EXCHANGE, true, false); }
}
