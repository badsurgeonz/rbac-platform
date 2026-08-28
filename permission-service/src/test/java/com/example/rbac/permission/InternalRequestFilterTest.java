package com.example.rbac.permission;

import com.example.rbac.common.InternalRequestSigner;
import com.example.rbac.common.SecurityContract;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockFilterChain;

import static org.junit.jupiter.api.Assertions.*;

class InternalRequestFilterTest {
    @Test
    void rejectsExpiredSignature() throws Exception {
        var request = new MockHttpServletRequest("GET", "/permissions/internal/roles");
        long timestamp = System.currentTimeMillis() / 1000 - 60;
        request.addHeader(SecurityContract.INTERNAL_TIMESTAMP_HEADER, String.valueOf(timestamp));
        request.addHeader(SecurityContract.INTERNAL_SIGNATURE_HEADER, InternalRequestSigner.sign("permission-secret", "GET", request.getRequestURI(), timestamp));
        var response = new MockHttpServletResponse();

        new InternalRequestFilter("permission-secret", 30).doFilter(request, response, new MockFilterChain());

        assertEquals(401, response.getStatus());
    }
}
