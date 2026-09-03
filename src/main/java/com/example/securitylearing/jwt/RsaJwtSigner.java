package com.example.securitylearing.jwt;

import java.security.PrivateKey;
import java.security.Signature;
import java.util.LinkedHashMap;
import java.util.Map;

/** Issues RS256 tokens, used as the legitimate counterpart in the Part B.5 algorithm-confusion scenario. */
public final class RsaJwtSigner {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private final PrivateKey privateKey;

    public RsaJwtSigner(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public String sign(Map<String, Object> claims) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "RS256");
        header.put("typ", "JWT");

        String headerB64 = Base64Url.encode(Json.toJson(header));
        String payloadB64 = Base64Url.encode(Json.toJson(claims));
        String signingInput = headerB64 + "." + payloadB64;

        byte[] signature = signRsa(signingInput);
        return signingInput + "." + Base64Url.encode(signature);
    }

    private byte[] signRsa(String data) {
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return signature.sign();
        } catch (Exception e) {
            throw new JwtException("Failed to compute RSA signature", e);
        }
    }
}
