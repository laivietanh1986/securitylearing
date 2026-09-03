package com.example.securitylearing.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Part A.1 — hand-rolled HS256 issuing: base64url(header) + "." + base64url(payload), signed with
 * HMAC-SHA256 via {@link Mac}. The header's {@code alg} is always hardcoded to "HS256" here — the
 * signer is not driven by caller input, which is what makes algorithm confusion (Part B.5) a
 * verifier-side problem, not an issuer-side one.
 */
public final class HmacJwtSigner {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final byte[] secret;

    public HmacJwtSigner(byte[] secret) {
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("HMAC secret must not be empty");
        }
        this.secret = secret.clone();
    }

    public String sign(Map<String, Object> claims) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "HS256");
        header.put("typ", "JWT");

        String headerB64 = Base64Url.encode(Json.toJson(header));
        String payloadB64 = Base64Url.encode(Json.toJson(claims));
        String signingInput = headerB64 + "." + payloadB64;

        byte[] signature = hmac(signingInput);
        return signingInput + "." + Base64Url.encode(signature);
    }

    private byte[] hmac(String data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new JwtException("Failed to compute HMAC signature", e);
        }
    }
}
