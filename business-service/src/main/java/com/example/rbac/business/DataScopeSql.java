package com.example.rbac.business;

import java.util.ArrayList;
import java.util.List;

/**
 * Converts a data scope policy into a parameterized SQL predicate that business
 * services must apply to every query. Empty or unknown scope rules default to deny.
 */
public final class DataScopeSql {
    public record Filter(String predicate, List<Object> args) {}

    private DataScopeSql() {}

    public static Filter filter(DataScopePolicyClient.Policy policy, Long userId) {
        if (policy == null) return new Filter("1 = 0", List.of());
        if (policy.allAllowed()) return new Filter("1 = 1", List.of());
        boolean hasGrant = policy.selfAllowed()
                || (policy.allowedOrgUnitIds() != null && !policy.allowedOrgUnitIds().isEmpty());
        if (!hasGrant) return new Filter("1 = 0", List.of());
        List<String> predicates = new ArrayList<>();
        List<Object> args = new ArrayList<>();

        if (policy.allowedTenants() != null && !policy.allowedTenants().isEmpty()) {
            predicates.add("tenant_id IN (" + placeholders(policy.allowedTenants().size()) + ")");
            args.addAll(policy.allowedTenants());
        }
        if (policy.selfAllowed()) {
            predicates.add("owner_user_id = ?");
            args.add(userId);
        }
        if (policy.allowedOrgUnitIds() != null && !policy.allowedOrgUnitIds().isEmpty()) {
            predicates.add("org_unit_id IN (" + placeholders(policy.allowedOrgUnitIds().size()) + ")");
            args.addAll(policy.allowedOrgUnitIds());
        }
        if (predicates.isEmpty()) return new Filter("1 = 0", List.of());
        return new Filter(String.join(" AND ", predicates), args);
    }

    public static String orderAndPageSql(String orderBy, int page, int size) {
        return " ORDER BY " + orderBy + " LIMIT ? OFFSET ?";
    }

    private static String placeholders(int count) {
        return String.join(",", java.util.Collections.nCopies(count, "?"));
    }
}
