package com.example.rbac.admin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.example.rbac")
public class AdminApplication {
    public static void main(String[] args) { SpringApplication.run(AdminApplication.class, args); }
}
