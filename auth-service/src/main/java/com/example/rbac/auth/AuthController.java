package com.example.rbac.auth;

import com.example.rbac.common.ApiResponse;
import com.example.rbac.common.JwtTokenService;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.*;
import java.time.Duration;
import java.util.*;
import java.util.UUID;

@RestController @RequestMapping("/auth")
public class AuthController {
    private final JwtTokenService jwt; private final StringRedisTemplate redis;
    public AuthController(JwtTokenService jwt, StringRedisTemplate redis) { this.jwt = jwt; this.redis = redis; }
    @PostMapping("/login")
    public ApiResponse<Map<String,String>> login(@RequestBody LoginRequest req, @RequestHeader(value="X-Device-Id", defaultValue="web") String device) {
        if (!"admin".equals(req.username()) || !"admin123".equals(req.password())) return ApiResponse.fail(401, "用户名或密码错误");
        String jti = UUID.randomUUID().toString(); String access = jwt.accessToken(1L, req.username(), device, List.of("user:read", "role:read", "audit:read", "permission:read", "permission:write"));
        String refresh = jwt.refreshToken(1L, device, jti); String session = "auth:session:1:" + device;
        String old = redis.opsForValue().get(session); if (old != null) for (String oldJti : old.split("\\|")) redis.opsForValue().set("auth:black:" + oldJti, "1", Duration.ofDays(7));
        String accessJti = jwt.parse(access).getId();
        redis.opsForValue().set(session, accessJti + "|" + jti, Duration.ofDays(7)); redis.opsForValue().set("auth:refresh:" + jti, "1:1:" + device, Duration.ofDays(7));
        return ApiResponse.ok(Map.of("accessToken", access, "refreshToken", refresh, "expiresIn", "900"));
    }
    @PostMapping("/logout") public ApiResponse<Void> logout(@RequestHeader("Authorization") String authorization) {
        String token = authorization.replaceFirst("^Bearer ", ""); var claims = jwt.parse(token); long seconds = Math.max(1, (claims.getExpiration().getTime()-System.currentTimeMillis())/1000);
        redis.opsForValue().set("auth:black:" + claims.getId(), "1", Duration.ofSeconds(seconds));
        String session = redis.opsForValue().get("auth:session:" + claims.getSubject() + ":" + claims.get("device"));
        if (session != null) for (String jti : session.split("\\|")) redis.opsForValue().set("auth:black:" + jti, "1", Duration.ofDays(7));
        return ApiResponse.ok(null);
    }
    @PostMapping("/refresh")
    public ApiResponse<Map<String, String>> refresh(@RequestBody RefreshRequest req) {
        try {
            var claims = jwt.parse(req.refreshToken());
            String oldJti = claims.getId();
            String sessionData = redis.opsForValue().get("auth:refresh:" + oldJti);
            if (!"refresh".equals(claims.get("type")) || sessionData == null) return ApiResponse.fail(401, "Refresh Token 已失效");
            String[] session = sessionData.split(":", 3); String device = session[2]; String newJti = UUID.randomUUID().toString();
            String access = jwt.accessToken(Long.valueOf(session[0]), "admin", device, List.of("user:read", "role:read", "audit:read", "permission:read", "permission:write"));
            String refresh = jwt.refreshToken(Long.valueOf(session[0]), device, newJti);
            redis.opsForValue().set("auth:black:" + oldJti, "1", Duration.ofDays(7));
            redis.delete("auth:refresh:" + oldJti); redis.opsForValue().set("auth:refresh:" + newJti, sessionData, Duration.ofDays(7));
            return ApiResponse.ok(Map.of("accessToken", access, "refreshToken", refresh, "expiresIn", "900"));
        } catch (Exception e) { return ApiResponse.fail(401, "Refresh Token 无效或已过期"); }
    }
    public record LoginRequest(String username, String password) {}
    public record RefreshRequest(String refreshToken) {}
}
