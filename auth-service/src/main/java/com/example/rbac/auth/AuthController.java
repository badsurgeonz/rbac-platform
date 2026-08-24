package com.example.rbac.auth;

import com.example.rbac.common.ApiResponse;
import com.example.rbac.common.JwtTokenService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import com.alibaba.csp.sentinel.annotation.SentinelResource;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final JwtTokenService jwt;
    private final StringRedisTemplate redis;
    private final JdbcTemplate jdbc;
    private final PasswordEncoder passwordEncoder;
    private static final Duration REFRESH_TTL = Duration.ofDays(7);
    private static final DefaultRedisScript<Long> ROTATE_REFRESH = new DefaultRedisScript<>("""
            local current = redis.call('GET', KEYS[1])
            if current ~= ARGV[1] then return 0 end
            redis.call('DEL', KEYS[1])
            redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
            redis.call('SET', KEYS[3], '1', 'EX', ARGV[3])
            redis.call('SET', KEYS[4], ARGV[4], 'EX', ARGV[3])
            return 1
            """, Long.class);

    public AuthController(JwtTokenService jwt, StringRedisTemplate redis, JdbcTemplate jdbc, PasswordEncoder passwordEncoder) {
        this.jwt = jwt; this.redis = redis; this.jdbc = jdbc; this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    @SentinelResource("auth:login")
    public ApiResponse<Map<String, String>> login(@Valid @RequestBody LoginRequest req,
                                                  @RequestHeader(value = "X-Device-Id", defaultValue = "web") String device,
                                                  @RequestHeader(value = "X-Forwarded-For", defaultValue = "unknown") String clientIp) {
        String failureKey = "auth:login:fail:" + clientIp + ":" + req.username();
        String failures = redis.opsForValue().get(failureKey);
        if (failures != null && Integer.parseInt(failures) >= 5) return ApiResponse.fail(429, "登录失败次数过多，请稍后重试");
        UserAccount user = findByUsername(req.username());
        if (user == null || user.status() != 1 || !passwordEncoder.matches(req.password(), user.passwordHash())) {
            Long count = redis.opsForValue().increment(failureKey);
            if (count != null && count == 1) redis.expire(failureKey, Duration.ofMinutes(10));
            return ApiResponse.fail(401, "用户名或密码错误");
        }
        redis.delete(failureKey);
        return issueTokens(user, device);
    }

    @PostMapping("/logout")
    public ApiResponse<Void> logout(@RequestHeader("Authorization") String authorization) {
        String token = authorization.replaceFirst("^Bearer ", "");
        var claims = jwt.parse(token);
        long seconds = Math.max(1, (claims.getExpiration().getTime() - System.currentTimeMillis()) / 1000);
        redis.opsForValue().set("auth:black:" + claims.getId(), "1", Duration.ofSeconds(seconds));
        String sessionKey = "auth:session:" + claims.getSubject() + ":" + claims.get("device");
        String session = redis.opsForValue().get(sessionKey);
        if (session != null) for (String jti : session.split("\\|")) redis.opsForValue().set("auth:black:" + jti, "1", Duration.ofDays(7));
        redis.delete(sessionKey);
        return ApiResponse.ok(null);
    }

    @PostMapping("/refresh")
    public ApiResponse<Map<String, String>> refresh(@Valid @RequestBody RefreshRequest req) {
        try {
            var claims = jwt.parse(req.refreshToken());
            String oldJti = claims.getId();
            String sessionData = redis.opsForValue().get("auth:refresh:" + oldJti);
            if (!"refresh".equals(claims.get("type")) || sessionData == null) return ApiResponse.fail(401, "Refresh Token 已失效");
            String[] session = sessionData.split(":", 3);
            UserAccount user = findById(Long.valueOf(session[0]));
            if (user == null || user.status() != 1) return ApiResponse.fail(401, "用户不可用");
            String device = session[2];
            String newJti = UUID.randomUUID().toString();
            Set<String> permissions = resolvePermissions(user.id());
            String access = jwt.accessToken(user.id(), user.username(), device, permissions);
            String refresh = jwt.refreshToken(user.id(), device, newJti);
            String newSession = jwt.parse(access).getId() + "|" + newJti;
            Long rotated = redis.execute(ROTATE_REFRESH,
                    List.of("auth:refresh:" + oldJti, "auth:refresh:" + newJti,
                            "auth:black:" + oldJti, "auth:session:" + user.id() + ":" + device),
                    sessionData, user.id() + ":1:" + device, String.valueOf(REFRESH_TTL.toSeconds()), newSession);
            if (!Long.valueOf(1).equals(rotated)) {
                revokeDeviceSession(user.id(), device);
                return ApiResponse.fail(401, "Refresh Token 已重放，会话已撤销");
            }
            return ApiResponse.ok(Map.of("accessToken", access, "refreshToken", refresh, "expiresIn", "900"));
        } catch (Exception e) { return ApiResponse.fail(401, "Refresh Token 无效或已过期"); }
    }

    private ApiResponse<Map<String, String>> issueTokens(UserAccount user, String device) {
        String refreshJti = UUID.randomUUID().toString();
        String access = jwt.accessToken(user.id(), user.username(), device, resolvePermissions(user.id()));
        String refresh = jwt.refreshToken(user.id(), device, refreshJti);
        String sessionKey = "auth:session:" + user.id() + ":" + device;
        String old = redis.opsForValue().get(sessionKey);
        if (old != null) for (String oldJti : old.split("\\|")) redis.opsForValue().set("auth:black:" + oldJti, "1", Duration.ofDays(7));
        redis.opsForValue().set(sessionKey, jwt.parse(access).getId() + "|" + refreshJti, Duration.ofDays(7));
        redis.opsForValue().set("auth:refresh:" + refreshJti, user.id() + ":1:" + device, REFRESH_TTL);
        return ApiResponse.ok(Map.of("accessToken", access, "refreshToken", refresh, "expiresIn", "900"));
    }

    private UserAccount findByUsername(String username) {
        List<UserAccount> users = jdbc.query("SELECT id, username, password_hash, status FROM sys_user WHERE username = ?", userRowMapper(), username);
        return users.isEmpty() ? null : users.get(0);
    }

    private UserAccount findById(Long id) {
        List<UserAccount> users = jdbc.query("SELECT id, username, password_hash, status FROM sys_user WHERE id = ?", userRowMapper(), id);
        return users.isEmpty() ? null : users.get(0);
    }

    private org.springframework.jdbc.core.RowMapper<UserAccount> userRowMapper() {
        return (rs, rowNum) -> new UserAccount(rs.getLong("id"), rs.getString("username"), rs.getString("password_hash"), rs.getInt("status"));
    }

    private Set<String> resolvePermissions(Long userId) {
        return new HashSet<>(jdbc.queryForList("""
                WITH RECURSIVE role_tree AS (
                    SELECT r.id, r.parent_id FROM sys_role r
                    JOIN sys_user_role ur ON ur.role_id = r.id WHERE ur.user_id = ?
                    UNION ALL
                    SELECT parent.id, parent.parent_id FROM sys_role parent
                    JOIN role_tree child ON child.parent_id = parent.id
                )
                SELECT DISTINCT p.code FROM role_tree rt
                JOIN sys_role_permission rp ON rp.role_id = rt.id
                JOIN sys_permission p ON p.id = rp.permission_id
                WHERE p.status = 1
                """, String.class, userId));
    }

    private void revokeDeviceSession(Long userId, String device) {
        String sessionKey = "auth:session:" + userId + ":" + device;
        String session = redis.opsForValue().get(sessionKey);
        if (session != null) {
            for (String jti : session.split("\\|")) {
                redis.opsForValue().set("auth:black:" + jti, "1", REFRESH_TTL);
            }
        }
        redis.delete(sessionKey);
    }

    record UserAccount(Long id, String username, String passwordHash, int status) {}
    public record LoginRequest(@NotBlank String username, @NotBlank String password) {}
    public record RefreshRequest(@NotBlank String refreshToken) {}
}
