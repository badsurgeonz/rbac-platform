package com.example.rbac.auth;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication(scanBasePackages = "com.example.rbac") public class AuthApplication { public static void main(String[] args) { SpringApplication.run(AuthApplication.class, args); } }
