package com.example.rbac.auth;

import com.example.rbac.common.ApiResponse;
import com.example.rbac.common.JwtTokenService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final JwtTokenService jwt;
    private final StringRedisTemplate redis;
    private final JdbcTemplate jdbc;
    private final PasswordEncoder passwordEncoder;

    public AuthController(JwtTokenService jwt, StringRedisTemplate redis, JdbcTemplate jdbc, PasswordEncoder passwordEncoder) {
        this.jwt = jwt; this.redis = redis; this.jdbc = jdbc; this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ApiResponse<Map<String, String>> login(@Valid @RequestBody LoginRequest req,
                                                  @RequestHeader(value = "X-Device-Id", defaultValue = "web") String device) {
        UserAccount user = findByUsername(req.username());
        if (user == null || user.status() != 1 || !passwordEncoder.matches(req.password(), user.passwordHash())) {
            return ApiResponse.fail(401, "用户名或密码错误");
        }
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
            String access = jwt.accessToken(user.id(), user.username(), device, defaultPermissions());
            String refresh = jwt.refreshToken(user.id(), device, newJti);
            redis.opsForValue().set("auth:black:" + oldJti, "1", Duration.ofDays(7));
            redis.delete("auth:refresh:" + oldJti);
            redis.opsForValue().set("auth:refresh:" + newJti, user.id() + ":1:" + device, Duration.ofDays(7));
            return ApiResponse.ok(Map.of("accessToken", access, "refreshToken", refresh, "expiresIn", "900"));
        } catch (Exception e) { return ApiResponse.fail(401, "Refresh Token 无效或已过期"); }
    }

    private ApiResponse<Map<String, String>> issueTokens(UserAccount user, String device) {
        String refreshJti = UUID.randomUUID().toString();
        String access = jwt.accessToken(user.id(), user.username(), device, defaultPermissions());
        String refresh = jwt.refreshToken(user.id(), device, refreshJti);
        String sessionKey = "auth:session:" + user.id() + ":" + device;
        String old = redis.opsForValue().get(sessionKey);
        if (old != null) for (String oldJti : old.split("\\|")) redis.opsForValue().set("auth:black:" + oldJti, "1", Duration.ofDays(7));
        redis.opsForValue().set(sessionKey, jwt.parse(access).getId() + "|" + refreshJti, Duration.ofDays(7));
        redis.opsForValue().set("auth:refresh:" + refreshJti, user.id() + ":1:" + device, Duration.ofDays(7));
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

    private List<String> defaultPermissions() { return List.of("user:read", "role:read", "audit:read", "permission:read", "permission:write"); }

    record UserAccount(Long id, String username, String passwordHash, int status) {}
    public record LoginRequest(@NotBlank String username, @NotBlank String password) {}
    public record RefreshRequest(@NotBlank String refreshToken) {}
}
