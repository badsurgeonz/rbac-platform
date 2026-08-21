package com.example.rbac.permission;

import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.config.SimpleRabbitListenerContainerFactory;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PermissionMessagingConfiguration {
    public static final String EXCHANGE = "rbac.events";
    public static final String AUDIT_QUEUE = "rbac.audit";
    @Bean TopicExchange rbacExchange() { return new TopicExchange(EXCHANGE, true, false); }
    @Bean Queue auditQueue() { return QueueBuilder.durable(AUDIT_QUEUE).build(); }
    @Bean Binding auditBinding(Queue auditQueue, TopicExchange rbacExchange) { return BindingBuilder.bind(auditQueue).to(rbacExchange).with("#"); }
    @Bean Jackson2JsonMessageConverter jsonMessageConverter() { return new Jackson2JsonMessageConverter(); }
    @Bean SimpleRabbitListenerContainerFactory rabbitListenerContainerFactory(org.springframework.amqp.rabbit.connection.ConnectionFactory connectionFactory, Jackson2JsonMessageConverter converter) {
        var factory = new SimpleRabbitListenerContainerFactory(); factory.setConnectionFactory(connectionFactory); factory.setMessageConverter(converter); return factory;
    }
}
