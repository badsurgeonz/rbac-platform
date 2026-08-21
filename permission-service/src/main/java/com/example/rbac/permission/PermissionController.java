package com.example.rbac.permission;

import com.example.rbac.common.ApiResponse;
import org.springframework.web.bind.annotation.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController @RequestMapping("/permissions")
public class PermissionController {
    private final Map<Long, Set<String>> userPermissions = new ConcurrentHashMap<>(Map.of(1L, Set.of("user:read","role:read","audit:read","permission:write")));
    @GetMapping("/users/{userId}") public ApiResponse<Set<String>> permissions(@PathVariable Long userId) { return ApiResponse.ok(userPermissions.getOrDefault(userId, Set.of())); }
    @PutMapping("/users/{userId}") public ApiResponse<Void> replace(@PathVariable Long userId, @RequestBody Set<String> permissions) { userPermissions.put(userId, Set.copyOf(permissions)); return ApiResponse.ok(null); }
}
