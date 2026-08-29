package com.example.rbac.permission;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataScopePolicyResolutionTest {
    @Test
    void allScopeAllowsEverythingAndClearsTenantRestriction() {
        var policy = PermissionController.resolvePolicy(7L,
                List.of(new PermissionController.ScopeRule("ALL", null)), Set.of(1L), Set.of("T1"), id -> Set.of(id));
        assertTrue(policy.allAllowed());
        assertTrue(policy.allowedTenants().isEmpty());
    }

    @Test
    void selfScopeOnly() {
        var policy = PermissionController.resolvePolicy(7L,
                List.of(new PermissionController.ScopeRule("SELF", null)), Set.of(1L), Set.of("T1"), id -> Set.of(id));
        assertFalse(policy.allAllowed());
        assertTrue(policy.selfAllowed());
        assertEquals(Set.of("T1"), policy.allowedTenants());
        assertTrue(policy.allowedOrgUnitIds().isEmpty());
    }

    @Test
    void departmentScopeOnlyIncludesOrgUserBelongsTo() {
        var policy = PermissionController.resolvePolicy(7L,
                List.of(new PermissionController.ScopeRule("DEPARTMENT", 2L)), Set.of(1L, 2L), Set.of("T1"), id -> Set.of(id));
        assertEquals(Set.of(2L), policy.allowedOrgUnitIds());
        assertEquals(Set.of("T1"), policy.allowedTenants());
    }

    @Test
    void departmentScopeOfOrgUserDoesNotBelongToIsIgnored() {
        var policy = PermissionController.resolvePolicy(7L,
                List.of(new PermissionController.ScopeRule("DEPARTMENT", 9L)), Set.of(1L, 2L), Set.of("T1"), id -> Set.of(id));
        assertTrue(policy.allowedOrgUnitIds().isEmpty());
    }

    @Test
    void descendantsScopeExpandsUsingResolver() {
        var policy = PermissionController.resolvePolicy(7L,
                List.of(new PermissionController.ScopeRule("DEPARTMENT_AND_DESCENDANTS", 1L)), Set.of(1L),
                Set.of("T1"), id -> id == 1L ? Set.of(1L, 2L, 3L) : Set.of(id));
        assertEquals(Set.of(1L, 2L, 3L), policy.allowedOrgUnitIds());
    }

    @Test
    void customScopeIsRejected() {
        var policy = PermissionController.resolvePolicy(7L,
                List.of(new PermissionController.ScopeRule("CUSTOM", null)), Set.of(1L), Set.of("T1"), id -> Set.of(id));
        assertFalse(policy.allAllowed());
        assertFalse(policy.selfAllowed());
        assertTrue(policy.allowedOrgUnitIds().isEmpty());
        assertEquals(Set.of("T1"), policy.allowedTenants());
    }

    @Test
    void unknownScopeTypeIsRejected() {
        var policy = PermissionController.resolvePolicy(7L,
                List.of(new PermissionController.ScopeRule("NONSENSE", null)), Set.of(1L), Set.of("T1"), id -> Set.of(id));
        assertFalse(policy.allAllowed());
        assertTrue(policy.allowedOrgUnitIds().isEmpty());
    }

    @Test
    void tenantRestrictionComesFromUserOrgUnits() {
        var policy = PermissionController.resolvePolicy(7L,
                List.of(new PermissionController.ScopeRule("DEPARTMENT", 2L)), Set.of(2L), Set.of("T2"), id -> Set.of(id));
        assertEquals(Set.of("T2"), policy.allowedTenants());
    }
}
