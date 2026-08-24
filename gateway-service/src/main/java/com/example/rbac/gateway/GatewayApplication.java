package com.example.rbac.gateway;

import com.example.rbac.common.InternalRequestSigner;
import com.example.rbac.common.JwtTokenService;
import com.example.rbac.common.SecurityContract;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

@SpringBootApplication(scanBasePackages = "com.example.rbac")
public class GatewayApplication {
    public static void main(String[] args) { SpringApplication.run(GatewayApplication.class, args); }

    @Bean
    GlobalFilter authenticationFilter(JwtTokenService jwt, ReactiveStringRedisTemplate redis,
                                      @Value("${security.internal.secret}") String internalSecret,
                                      @Value("${security.internal.timestamp-skew-seconds:30}") long timestampSkew) {
        return (exchange, chain) -> {
            String path = exchange.getRequest().getURI().getPath();
            if (isPublic(path)) return forward(exchange, chain, internalSecret);

            String authorization = exchange.getRequest().getHeaders().getFirst("Authorization");
            if (authorization == null || !authorization.startsWith("Bearer ") || authorization.length() <= 7) {
                return reject(exchange, HttpStatus.UNAUTHORIZED);
            }
            try {
                var claims = jwt.parse(authorization.substring(7));
                if (!SecurityContract.ACCESS_TOKEN.equals(claims.get("type"))) {
                    return reject(exchange, HttpStatus.UNAUTHORIZED);
                }
                String required = requiredPermission(exchange);
                @SuppressWarnings("unchecked")
                List<String> permissions = (List<String>) claims.get("permissions");
                if (required != null && (permissions == null || !permissions.contains(required))) {
                    return reject(exchange, HttpStatus.FORBIDDEN);
                }
                return redis.hasKey("auth:black:" + claims.getId()).flatMap(blocked -> {
                    if (blocked) return reject(exchange, HttpStatus.UNAUTHORIZED);
                    var request = exchange.getRequest().mutate()
                            .headers(headers -> {
                                headers.remove(SecurityContract.USER_ID_HEADER);
                                headers.remove(SecurityContract.USERNAME_HEADER);
                                headers.remove(SecurityContract.DEVICE_ID_HEADER);
                                headers.remove(SecurityContract.INTERNAL_TIMESTAMP_HEADER);
                                headers.remove(SecurityContract.INTERNAL_SIGNATURE_HEADER);
                            })
                            .header(SecurityContract.USER_ID_HEADER, claims.getSubject())
                            .header(SecurityContract.USERNAME_HEADER, String.valueOf(claims.get("username")))
                            .header(SecurityContract.DEVICE_ID_HEADER, String.valueOf(claims.get("device")))
                            .build();
                    return forward(exchange.mutate().request(request).build(), chain, internalSecret);
                });
            } catch (Exception exception) {
                return reject(exchange, HttpStatus.UNAUTHORIZED);
            }
        };
    }

    private static boolean isPublic(String path) {
        return path.equals("/auth/login") || path.equals("/auth/refresh") || path.equals("/actuator/health");
    }

    private static String requiredPermission(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        if (route == null) return null;
        String defaultPermission = String.valueOf(route.getMetadata().getOrDefault("required-permission", ""));
        if (defaultPermission.isBlank()) return null;
        String method = exchange.getRequest().getMethod().name();
        String writeMethods = String.valueOf(route.getMetadata().getOrDefault("write-methods", ""));
        return Arrays.stream(writeMethods.split(","))
                .map(String::trim)
                .anyMatch(method::equalsIgnoreCase) ? "permission:write" : defaultPermission;
    }

    private static Mono<Void> forward(ServerWebExchange exchange, org.springframework.cloud.gateway.filter.GatewayFilterChain chain,
                                      String secret) {
        long timestamp = System.currentTimeMillis() / 1000;
        String path = exchange.getRequest().getURI().getPath();
        var request = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove(SecurityContract.INTERNAL_TIMESTAMP_HEADER);
                    headers.remove(SecurityContract.INTERNAL_SIGNATURE_HEADER);
                })
                .header(SecurityContract.INTERNAL_TIMESTAMP_HEADER, String.valueOf(timestamp))
                .header(SecurityContract.INTERNAL_SIGNATURE_HEADER,
                        InternalRequestSigner.sign(secret, exchange.getRequest().getMethod().name(), path, timestamp))
                .build();
        return chain.filter(exchange.mutate().request(request).build());
    }

    private static Mono<Void> reject(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }
}
