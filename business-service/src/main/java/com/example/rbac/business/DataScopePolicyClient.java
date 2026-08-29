package com.example.rbac.business;

import com.example.rbac.common.ApiResponse;
import com.example.rbac.common.InternalRequestSigner;
import com.example.rbac.common.SecurityContract;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Set;

@Component
public class DataScopePolicyClient {
    private final DiscoveryClient discoveryClient;
    private final String secret;
    public DataScopePolicyClient(DiscoveryClient discoveryClient, @Value("${security.internal.secret}") String secret) {
        this.discoveryClient = discoveryClient; this.secret = secret;
    }
    public Policy policy(Long userId) {
        List<ServiceInstance> instances = discoveryClient.getInstances("permission-service");
        if (instances.isEmpty()) throw new IllegalStateException("permission-service is unavailable");
        String path = "/permissions/internal/users/" + userId + "/data-scope-policy";
        long timestamp = System.currentTimeMillis() / 1000;
        ApiResponse<Policy> response = RestClient.create(instances.get(0).getUri()).get().uri(path)
                .header(SecurityContract.INTERNAL_TIMESTAMP_HEADER, String.valueOf(timestamp))
                .header(SecurityContract.INTERNAL_SIGNATURE_HEADER, InternalRequestSigner.sign(secret, "GET", path, timestamp))
                .retrieve().body(new ParameterizedTypeReference<>() {});
        if (response == null || response.data() == null || response.code() != 0) throw new IllegalStateException("invalid data scope policy");
        return response.data();
    }
    public record Policy(boolean allAllowed, boolean selfAllowed, Set<Long> allowedOrgUnitIds) {}
}
