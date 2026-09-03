package com.example.securitylearing.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * A parsed (but not yet verified) compact JWT: {@code base64url(header).base64url(payload).base64url(signature)}.
 * Parsing only handles structure/encoding; it makes no trust decision about the content.
 */
record JwtToken(
        String headerB64,
        String payloadB64,
        String signatureB64,
        Map<String, Object> header,
        Map<String, Object> payload,
        byte[] signature
) {

    /** The exact bytes that were (or should have been) signed. */
    String signingInput() {
        return headerB64 + "." + payloadB64;
    }

    static JwtToken parse(String token) {
        if (token == null || token.isEmpty()) {
            throw new JwtException("Token is null or empty");
        }
        // -1 limit: keep trailing empty strings so "header.payload." (alg:none, empty signature) is still 3 parts.
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new JwtException("Malformed JWT: expected 3 dot-separated segments, got " + parts.length);
        }

        String headerJson = new String(Base64Url.decode(parts[0]), StandardCharsets.UTF_8);
        String payloadJson = new String(Base64Url.decode(parts[1]), StandardCharsets.UTF_8);
        byte[] signature = parts[2].isEmpty() ? new byte[0] : Base64Url.decode(parts[2]);

        return new JwtToken(parts[0], parts[1], parts[2], Json.toMap(headerJson), Json.toMap(payloadJson), signature);
    }
}
