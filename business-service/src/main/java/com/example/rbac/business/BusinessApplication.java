package com.example.rbac.business;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.example.rbac.business")
public class BusinessApplication {
    public static void main(String[] args) { SpringApplication.run(BusinessApplication.class, args); }
}
