package com.example.rbac.admin;

import com.example.rbac.common.InternalRequestSigner;
import com.example.rbac.common.SecurityContract;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class InternalRequestFilter extends OncePerRequestFilter {
    private final String secret; private final long skew;
    public InternalRequestFilter(String secret, long skew) { this.secret = secret; this.skew = skew; }
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
