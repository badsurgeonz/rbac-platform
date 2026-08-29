package com.example.rbac.business;

import com.example.rbac.business.DataScopePolicyClient.Policy;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataScopeSqlTest {
    @Test
    void allAllowedProducesNoRestriction() {
        DataScopeSql.Filter filter = DataScopeSql.filter(new Policy(true, false, Set.of(), Set.of()), 7L);
        assertEquals("1 = 1", filter.predicate());
        assertTrue(filter.args().isEmpty());
    }

    @Test
    void selfScopeOnlyRestrictsOwner() {
        DataScopeSql.Filter filter = DataScopeSql.filter(new Policy(false, true, Set.of(), Set.of()), 7L);
        assertEquals("owner_user_id = ?", filter.predicate());
        assertEquals(List.of(7L), filter.args());
    }

    @Test
    void departmentScopeRestrictsOrgAndTenant() {
        DataScopeSql.Filter filter = DataScopeSql.filter(new Policy(false, false, Set.of(2L, 3L), Set.of("T1")), 7L);
        assertEquals("tenant_id IN (?) AND org_unit_id IN (?,?)", filter.predicate());
        assertEquals("T1", filter.args().get(0));
        assertTrue(filter.args().subList(1, 3).containsAll(List.of(2L, 3L)));
    }

    @Test
    void selfPlusDepartmentCombinesWithAnd() {
        DataScopeSql.Filter filter = DataScopeSql.filter(new Policy(false, true, Set.of(2L), Set.of("T1")), 7L);
        assertEquals("tenant_id IN (?) AND owner_user_id = ? AND org_unit_id IN (?)", filter.predicate());
    }

    @Test
    void emptyPolicyDeniesEverything() {
        DataScopeSql.Filter filter = DataScopeSql.filter(new Policy(false, false, Set.of(), Set.of()), 7L);
        assertEquals("1 = 0", filter.predicate());
    }

    @Test
    void customScopeWithTenantButNoGrantDeniesEverything() {
        DataScopeSql.Filter filter = DataScopeSql.filter(new Policy(false, false, Set.of(), Set.of("T1")), 7L);
        assertEquals("1 = 0", filter.predicate());
    }

    @Test
    void nullPolicyDeniesEverything() {
        assertEquals("1 = 0", DataScopeSql.filter(null, 7L).predicate());
    }

    @Test
    void selfScopeWithoutTenantStillRestrictsOwner() {
        DataScopeSql.Filter filter = DataScopeSql.filter(new Policy(false, true, Set.of(), Set.of("T1")), 7L);
        assertEquals("tenant_id IN (?) AND owner_user_id = ?", filter.predicate());
    }

    @Test
    void departmentScopeWithoutTenantOnlyRestrictsOrg() {
        DataScopeSql.Filter filter = DataScopeSql.filter(new Policy(false, false, Set.of(2L), Set.of()), 7L);
        assertEquals("org_unit_id IN (?)", filter.predicate());
    }
}
