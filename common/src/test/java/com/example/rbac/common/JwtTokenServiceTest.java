package com.example.rbac.common;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenServiceTest {
    private final JwtTokenService service = new JwtTokenService("test-secret-test-secret-test-secret-32", 900, 604800, "test-issuer", "test-audience");

    @Test
    void accessTokenContainsIdentityAndType() {
        String token = service.accessToken(7L, "alice", "web", List.of("user:read"), 1);
        var claims = service.parse(token);
        assertEquals("7", claims.getSubject());
        assertEquals("alice", claims.get("username"));
        assertEquals("access", claims.get("type"));
        assertEquals(1, claims.get("authVersion", Integer.class));
        assertEquals("test-issuer", claims.getIssuer());
    }

    @Test
    void refreshTokenIsNotAcceptedAsAccessToken() {
        String token = service.refreshToken(7L, "web", "refresh-jti");
        assertEquals("refresh", service.parse(token).get("type"));
    }

    @Test
    void tokenWithWrongIssuerCannotBeParsed() {
        JwtTokenService other = new JwtTokenService("test-secret-test-secret-test-secret-32", 900, 604800, "other", "test-audience");
        String token = other.accessToken(7L, "alice", "web", List.of(), 1);
        assertThrows(Exception.class, () -> service.parse(token));
    }
}
