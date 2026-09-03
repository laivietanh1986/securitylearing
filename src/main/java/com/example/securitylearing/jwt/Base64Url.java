package com.example.securitylearing.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** RFC 7515 base64url (no padding) — plain base64 uses '+' '/' '=' which are not URL-safe. */
final class Base64Url {

    private Base64Url() {
    }

    static String encode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    static String encode(String data) {
        return encode(data.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] decode(String data) {
        try {
            return Base64.getUrlDecoder().decode(data);
        } catch (IllegalArgumentException e) {
            throw new JwtException("Malformed base64url segment", e);
        }
    }
}
