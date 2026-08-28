package com.example.rbac.audit;

import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.config.RetryInterceptorBuilder;
import org.springframework.amqp.rabbit.config.SimpleRabbitListenerContainerFactory;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.retry.interceptor.RetryOperationsInterceptor;

import java.util.Map;

@Configuration
public class AuditMessagingConfiguration {
    public static final String EXCHANGE = "rbac.events";
    public static final String AUDIT_QUEUE = "rbac.audit.v2";
    public static final String DEAD_LETTER_EXCHANGE = "rbac.events.dlx.v2";
    public static final String DEAD_LETTER_QUEUE = "rbac.audit.dlq.v2";

    @Bean TopicExchange rbacExchange() { return new TopicExchange(EXCHANGE, true, false); }
    @Bean TopicExchange deadLetterExchange() { return new TopicExchange(DEAD_LETTER_EXCHANGE, true, false); }
    @Bean Queue deadLetterQueue() { return QueueBuilder.durable(DEAD_LETTER_QUEUE).build(); }
    @Bean Queue auditQueue() { return QueueBuilder.durable(AUDIT_QUEUE).withArguments(Map.of(
            "x-dead-letter-exchange", DEAD_LETTER_EXCHANGE,
            "x-dead-letter-routing-key", "audit.dead")).build(); }
    @Bean Binding auditBinding(Queue auditQueue, TopicExchange rbacExchange) { return BindingBuilder.bind(auditQueue).to(rbacExchange).with("#"); }
    @Bean Binding deadLetterBinding(Queue deadLetterQueue, TopicExchange deadLetterExchange) { return BindingBuilder.bind(deadLetterQueue).to(deadLetterExchange).with("audit.dead"); }
    @Bean Jackson2JsonMessageConverter jsonMessageConverter() { return new Jackson2JsonMessageConverter(); }
    @Bean RetryOperationsInterceptor retryInterceptor() {
        return RetryInterceptorBuilder.stateless().maxAttempts(3).backOffOptions(1000, 2.0, 10000).build();
    }
    @Bean SimpleRabbitListenerContainerFactory rabbitListenerContainerFactory(
            org.springframework.amqp.rabbit.connection.ConnectionFactory connectionFactory,
            Jackson2JsonMessageConverter converter, RetryOperationsInterceptor retryInterceptor) {
        var factory = new SimpleRabbitListenerContainerFactory();
        factory.setConnectionFactory(connectionFactory);
        factory.setMessageConverter(converter);
        factory.setDefaultRequeueRejected(false);
        factory.setAdviceChain(retryInterceptor);
        return factory;
    }
}
