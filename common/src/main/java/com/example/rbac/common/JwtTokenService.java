package com.example.rbac.common;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Service
public class JwtTokenService {
    private final SecretKey key;
    private final long accessSeconds;
    private final long refreshSeconds;
    private final String issuer;
    private final String audience;
    public JwtTokenService(@Value("${security.jwt.secret}") String secret,
                           @Value("${security.jwt.access-seconds:900}") long accessSeconds,
                           @Value("${security.jwt.refresh-seconds:604800}") long refreshSeconds,
                           @Value("${security.jwt.issuer:rbac-platform}") String issuer,
                           @Value("${security.jwt.audience:rbac-api}") String audience) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)); this.accessSeconds = accessSeconds; this.refreshSeconds = refreshSeconds; this.issuer = issuer; this.audience = audience;
    }
    public String accessToken(Long userId, String username, String device, java.util.Collection<String> permissions, long authVersion) {
        Instant now = Instant.now();
        return Jwts.builder().id(java.util.UUID.randomUUID().toString()).issuer(issuer).audience().add(audience).and().subject(String.valueOf(userId)).claim("username", username).claim("device", device).claim("type", "access").claim("authVersion", authVersion)
                .claim("permissions", permissions).issuedAt(Date.from(now)).expiration(Date.from(now.plusSeconds(accessSeconds)))
                .signWith(key).compact();
    }
    public String refreshToken(Long userId, String device, String jti) {
        return Jwts.builder().id(jti).issuer(issuer).audience().add(audience).and().subject(String.valueOf(userId)).claim("device", device).claim("type", "refresh")
                .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis() + refreshSeconds * 1000L)).signWith(key).compact();
    }
    public Claims parse(String token) { return Jwts.parser().verifyWith(key).requireIssuer(issuer).requireAudience(audience).build().parseSignedClaims(token).getPayload(); }
}
