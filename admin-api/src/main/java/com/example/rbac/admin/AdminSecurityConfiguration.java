package com.example.rbac.admin;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Configuration
public class AdminSecurityConfiguration {
    @Bean InternalRequestFilter internalRequestFilter(@Value("${security.internal.secret}") String secret, @Value("${security.internal.timestamp-skew-seconds:30}") long skew) { return new InternalRequestFilter(secret, skew); }
    @Bean SecurityFilterChain security(HttpSecurity http, InternalRequestFilter filter) throws Exception {
        return http.csrf(csrf -> csrf.disable()).addFilterBefore(filter, AnonymousAuthenticationFilter.class).authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).build();
    }
}
