package com.example.rbac.gateway;

import com.example.rbac.common.JwtTokenService;
import com.example.rbac.common.SecurityContract;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.ReactiveValueOperations;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class GatewaySecurityTest {
    private final JwtTokenService jwt = new JwtTokenService("gateway-test-secret-gateway-test-secret-32", 900, 604800, "issuer", "audience");

    @Test
    void rejectsUnauthenticatedRequest() {
        var exchange = exchange("GET", "/permissions");
        var chain = mock(GatewayFilterChain.class);
        var filter = filter(false, "1");

        filter.filter(exchange, chain).block();

        assertEquals(401, exchange.getResponse().getStatusCode().value());
        verifyNoInteractions(chain);
    }

    @Test
    void rejectsInternalPathAtPublicGateway() {
        var exchange = exchange("GET", "/permissions/internal/users/7/permissions");
        var chain = mock(GatewayFilterChain.class);

        filter(false, "1").filter(exchange, chain).block();

        assertEquals(404, exchange.getResponse().getStatusCode().value());
        verifyNoInteractions(chain);
    }

    @Test
    void forwardsTrustedIdentityAndReplacesClientHeaders() {
        String token = jwt.accessToken(7L, "alice", "web", List.of("permission:read"), 1);
        var exchange = exchange("GET", "/permissions").mutate()
                .request(MockServerHttpRequest.get("/permissions")
                        .header("Authorization", "Bearer " + token)
                        .header(SecurityContract.USER_ID_HEADER, "999")
                        .header(SecurityContract.USERNAME_HEADER, "attacker")
                        .build()).build();
        var chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());
        var redis = redis(false, "1");

        new GatewayApplication().authenticationFilter(jwt, redis, "internal-secret", 30).filter(exchange, chain).block();

        var captor = org.mockito.ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());
        var forwarded = captor.getValue().getRequest().getHeaders();
        assertEquals("7", forwarded.getFirst(SecurityContract.USER_ID_HEADER));
        assertEquals("alice", forwarded.getFirst(SecurityContract.USERNAME_HEADER));
        assertEquals("web", forwarded.getFirst(SecurityContract.DEVICE_ID_HEADER));
        assertEquals("permission:read", forwarded.getFirst(SecurityContract.PERMISSIONS_HEADER));
        assertNotEquals("999", forwarded.getFirst(SecurityContract.USER_ID_HEADER));
    }

    @Test
    void rejectsStaleUserVersion() {
        String token = jwt.accessToken(7L, "alice", "web", List.of(), 1);
        var exchange = exchange("GET", "/permissions").mutate().request(MockServerHttpRequest.get("/permissions")
                .header("Authorization", "Bearer " + token).build()).build();
        var chain = mock(GatewayFilterChain.class);

        new GatewayApplication().authenticationFilter(jwt, redis(false, "2"), "internal-secret", 30).filter(exchange, chain).block();

        assertEquals(401, exchange.getResponse().getStatusCode().value());
        verifyNoInteractions(chain);
    }

    @Test
    void rejectsRefreshTokenOnBusinessRoute() {
        String token = jwt.refreshToken(7L, "web", "refresh-jti");
        var exchange = exchange("GET", "/permissions").mutate().request(MockServerHttpRequest.get("/permissions")
                .header("Authorization", "Bearer " + token).build()).build();
        var chain = mock(GatewayFilterChain.class);

        new GatewayApplication().authenticationFilter(jwt, redis(false, "1"), "internal-secret", 30).filter(exchange, chain).block();

        assertEquals(401, exchange.getResponse().getStatusCode().value());
        verifyNoInteractions(chain);
    }

    private MockServerWebExchange exchange(String method, String path) {
        return MockServerWebExchange.from(MockServerHttpRequest.method(org.springframework.http.HttpMethod.valueOf(method), path).build());
    }

    private GlobalFilter filter(boolean blocked, String version) {
        return new GatewayApplication().authenticationFilter(jwt, redis(blocked, version), "internal-secret", 30);
    }

    private ReactiveStringRedisTemplate redis(boolean blocked, String version) {
        var redis = mock(ReactiveStringRedisTemplate.class);
        var values = mock(ReactiveValueOperations.class);
        when(redis.hasKey(anyString())).thenReturn(Mono.just(blocked));
        when(redis.opsForValue()).thenReturn(values);
        when(values.get(anyString())).thenReturn(Mono.just(version));
        return redis;
    }
}
