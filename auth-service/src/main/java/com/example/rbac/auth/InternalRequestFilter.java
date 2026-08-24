package com.example.rbac.auth;

import com.example.rbac.common.InternalRequestSigner;
import com.example.rbac.common.SecurityContract;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class InternalRequestFilter extends OncePerRequestFilter {
    private final String secret;
    private final long timestampSkew;

    public InternalRequestFilter(@Value("${security.internal.secret}") String secret,
                                 @Value("${security.internal.timestamp-skew-seconds:30}") long timestampSkew) {
        this.secret = secret;
        this.timestampSkew = timestampSkew;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String timestamp = request.getHeader(SecurityContract.INTERNAL_TIMESTAMP_HEADER);
        String signature = request.getHeader(SecurityContract.INTERNAL_SIGNATURE_HEADER);
        boolean valid = false;
        try {
            valid = InternalRequestSigner.verify(secret, request.getMethod(), request.getRequestURI(),
                    Long.parseLong(timestamp), signature, timestampSkew);
        } catch (RuntimeException ignored) {
            // Invalid or missing internal credentials are rejected below.
        }
        if (!valid) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid internal request");
            return;
        }
        String principal = request.getHeader(SecurityContract.USER_ID_HEADER);
        if (principal == null || principal.isBlank()) principal = "gateway";
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(principal, null, java.util.List.of()));
        chain.doFilter(request, response);
    }
}
