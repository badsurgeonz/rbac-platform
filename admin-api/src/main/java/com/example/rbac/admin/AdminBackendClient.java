package com.example.rbac.admin;

import com.example.rbac.common.InternalRequestSigner;
import com.example.rbac.common.SecurityContract;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

@Component
public class AdminBackendClient {
    private final DiscoveryClient discoveryClient;
    private final String secret;
    private final ObjectMapper objectMapper;

    public AdminBackendClient(DiscoveryClient discoveryClient, @Value("${security.internal.secret}") String secret,
                              ObjectMapper objectMapper) {
        this.discoveryClient = discoveryClient;
        this.secret = secret;
        this.objectMapper = objectMapper;
    }

    public JsonNode get(String service, String path) { return request(service, HttpMethod.GET, path, null); }
    public JsonNode put(String service, String path, Object body) { return request(service, HttpMethod.PUT, path, body); }
    public JsonNode post(String service, String path, Object body) { return request(service, HttpMethod.POST, path, body); }
    public JsonNode delete(String service, String path) { return request(service, HttpMethod.DELETE, path, null); }
    public JsonNode putAsOperator(String service, String path, Object body, Long operatorId, String stepUpToken) {
        return request(service, HttpMethod.PUT, path, body, Map.of(SecurityContract.USER_ID_HEADER, String.valueOf(operatorId), SecurityContract.STEP_UP_TOKEN_HEADER, stepUpToken));
    }
    public JsonNode deleteAsOperator(String service, String path, Long operatorId, String stepUpToken) {
        return request(service, HttpMethod.DELETE, path, null, Map.of(SecurityContract.USER_ID_HEADER, String.valueOf(operatorId), SecurityContract.STEP_UP_TOKEN_HEADER, stepUpToken));
    }

    private JsonNode request(String service, HttpMethod method, String path, Object body) {
        return request(service, method, path, body, Map.of());
    }

    private JsonNode request(String service, HttpMethod method, String path, Object body, Map<String, String> extraHeaders) {
        List<ServiceInstance> instances = discoveryClient.getInstances(service);
        if (instances.isEmpty()) throw new IllegalStateException(service + " is unavailable");
        long timestamp = System.currentTimeMillis() / 1000;
        String signaturePath = path.split("\\?", 2)[0];
        var request = RestClient.create(instances.get(0).getUri()).method(method).uri(path)
                .header(SecurityContract.INTERNAL_TIMESTAMP_HEADER, String.valueOf(timestamp))
                .header(SecurityContract.INTERNAL_SIGNATURE_HEADER, InternalRequestSigner.sign(secret, method.name(), signaturePath, timestamp));
        extraHeaders.forEach(request::header);
        if (body != null) request.body(body);
        return request.retrieve().body(JsonNode.class);
    }
}
