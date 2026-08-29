package com.example.rbac.business;

import com.example.rbac.common.SecurityContract;
import com.example.rbac.common.InternalRequestSigner;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Configuration
public class BusinessSecurityConfiguration {
    @Bean
    InternalRequestFilter internalRequestFilter(@Value("${security.internal.secret}") String secret,
                                                @Value("${security.internal.timestamp-skew-seconds:30}") long skew) {
        return new InternalRequestFilter(secret, skew);
    }
    @Bean
    SecurityFilterChain security(HttpSecurity http, InternalRequestFilter filter) throws Exception {
        return http.csrf(csrf -> csrf.disable()).addFilterBefore(filter, AnonymousAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).build();
    }
    static class InternalRequestFilter extends OncePerRequestFilter {
        private final String secret; private final long skew;
        InternalRequestFilter(String secret, long skew) { this.secret = secret; this.skew = skew; }
        @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
            try {
                if (!InternalRequestSigner.verify(secret, request.getMethod(), request.getRequestURI(), Long.parseLong(request.getHeader(SecurityContract.INTERNAL_TIMESTAMP_HEADER)), request.getHeader(SecurityContract.INTERNAL_SIGNATURE_HEADER), skew)) {
                    response.sendError(401, "Invalid internal request"); return;
                }
            } catch (RuntimeException exception) { response.sendError(401, "Invalid internal request"); return; }
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("gateway", null, java.util.List.of()));
            chain.doFilter(request, response);
        }
    }
}
