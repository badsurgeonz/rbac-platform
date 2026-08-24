package com.example.rbac.common;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class InternalRequestSigner {
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private InternalRequestSigner() {}

    public static String sign(String secret, String method, String path, long timestamp) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            byte[] digest = mac.doFinal(canonical(method, path, timestamp).getBytes(StandardCharsets.UTF_8));
            return toHex(digest);
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to sign internal request", exception);
        }
    }

    public static boolean verify(String secret, String method, String path, long timestamp, String signature,
                                 long allowedSkewSeconds) {
        if (signature == null || Math.abs(System.currentTimeMillis() / 1000 - timestamp) > allowedSkewSeconds) {
            return false;
        }
        String expected = sign(secret, method, path, timestamp);
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
                signature.getBytes(StandardCharsets.US_ASCII));
    }

    private static String canonical(String method, String path, long timestamp) {
        return method.toUpperCase() + "\n" + path + "\n" + timestamp;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) result.append(String.format("%02x", value));
        return result.toString();
    }
}
