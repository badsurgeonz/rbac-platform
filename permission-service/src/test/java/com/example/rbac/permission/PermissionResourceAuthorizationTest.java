package com.example.rbac.permission;

import com.example.rbac.common.ApiResponse;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class PermissionResourceAuthorizationTest {
    @Test
    void userCannotReadAnotherUsersPermissionsWithoutUserReadPermission() {
        var jdbc = mock(JdbcTemplate.class);
        var controller = new PermissionController(jdbc, mock(StringRedisTemplate.class), mock(PermissionEventPublisher.class));

        ApiResponse<Set<String>> response = controller.permissions(99L, 7L, "permission:read");

        assertEquals(403, response.code());
        verifyNoInteractions(jdbc);
    }
}
