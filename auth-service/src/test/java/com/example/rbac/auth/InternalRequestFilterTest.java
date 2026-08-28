package com.example.rbac.auth;

import com.example.rbac.common.InternalRequestSigner;
import com.example.rbac.common.SecurityContract;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockFilterChain;

import static org.junit.jupiter.api.Assertions.*;

class InternalRequestFilterTest {
    private static final String SECRET = "auth-filter-test-secret";

    @Test
    void rejectsDirectRequestWithoutInternalSignature() throws Exception {
        var request = new MockHttpServletRequest("GET", "/auth/internal/users");
        var response = new MockHttpServletResponse();
        var chain = new MockFilterChain();

        new InternalRequestFilter(SECRET, 30).doFilter(request, response, chain);

        assertEquals(401, response.getStatus());
        assertNull(chain.getRequest());
    }

    @Test
    void acceptsCorrectSignature() throws Exception {
        long timestamp = System.currentTimeMillis() / 1000;
        var request = new MockHttpServletRequest("GET", "/auth/internal/users");
        request.addHeader(SecurityContract.INTERNAL_TIMESTAMP_HEADER, String.valueOf(timestamp));
        request.addHeader(SecurityContract.INTERNAL_SIGNATURE_HEADER, InternalRequestSigner.sign(SECRET, "GET", request.getRequestURI(), timestamp));
        var response = new MockHttpServletResponse();
        var chain = new MockFilterChain();

        new InternalRequestFilter(SECRET, 30).doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(chain.getRequest());
    }

    @Test
    void rejectsSignatureForDifferentPath() throws Exception {
        long timestamp = System.currentTimeMillis() / 1000;
        var request = new MockHttpServletRequest("GET", "/auth/internal/users");
        request.addHeader(SecurityContract.INTERNAL_TIMESTAMP_HEADER, String.valueOf(timestamp));
        request.addHeader(SecurityContract.INTERNAL_SIGNATURE_HEADER, InternalRequestSigner.sign(SECRET, "GET", "/auth/internal/other", timestamp));
        var response = new MockHttpServletResponse();

        new InternalRequestFilter(SECRET, 30).doFilter(request, response, new MockFilterChain());

        assertEquals(401, response.getStatus());
    }
}
