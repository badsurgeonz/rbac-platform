package com.example.rbac.permission;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Configuration
public class PermissionConfiguration {
    @Bean
    InternalRequestFilter internalRequestFilter(@Value("${security.internal.secret}") String secret,
                                                @Value("${security.internal.timestamp-skew-seconds:30}") long timestampSkew) {
        return new InternalRequestFilter(secret, timestampSkew);
    }

    @Bean
    SecurityFilterChain permissionSecurity(HttpSecurity http, InternalRequestFilter internalRequestFilter) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                .addFilterBefore(internalRequestFilter, AnonymousAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).build();
    }
}
