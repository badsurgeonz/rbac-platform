package com.example.rbac.permission;

import com.rabbitmq.client.ConnectionFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.containers.RabbitMQContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.DriverManager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers
@EnabledOnOs(OS.LINUX)
class InfrastructureContainersTest {
    @Container
    static final MySQLContainer<?> mysql = new MySQLContainer<>("mysql:8.0").withDatabaseName("rbac").withUsername("rbac").withPassword("rbac123");

    @Container
    static final GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

    @Container
    static final RabbitMQContainer rabbit = new RabbitMQContainer("rabbitmq:3-management");

    @Test
    void mysqlIsAcceptingConnections() throws Exception {
        assertTrue(mysql.isRunning());
        try (var connection = DriverManager.getConnection(mysql.getJdbcUrl(), mysql.getUsername(), mysql.getPassword()); var statement = connection.createStatement(); var result = statement.executeQuery("SELECT 1")) {
            result.next();
            assertEquals(1, result.getInt(1));
        }
    }

    @Test
    void redisIsReachable() throws Exception {
        var result = redis.execInContainer("redis-cli", "PING");
        assertEquals(0, result.getExitCode());
        assertEquals("PONG", result.getStdout().trim());
    }

    @Test
    void rabbitmqAcceptsAmqpConnections() throws Exception {
        var factory = new ConnectionFactory();
        factory.setUri(rabbit.getAmqpUrl());
        try (var connection = factory.newConnection()) { assertTrue(connection.isOpen()); }
    }
}
