package com.example.rbac.audit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication(scanBasePackages = "com.example.rbac")
@EnableScheduling
public class AuditApplication {
    public static void main(String[] args) { SpringApplication.run(AuditApplication.class, args); }
}
