package com.example.securitylearing.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Map;

/**
 * <b>Deliberately vulnerable. Exists only so Part B's attacks have something real to break, and so
 * {@link HmacJwtVerifier}/{@link RsaJwtVerifier} have something concrete to be compared against.
 * Never call this outside of tests.</b>
 *
 * <p>This mirrors a real, repeated class of JWT library bugs (e.g. early node {@code jsonwebtoken}
 * CVE-2015-9235-style issues): a single {@code verify(token, key)} entry point that trusts the
 * token's own {@code alg} header to decide <i>both</i> which cryptographic primitive to run
 * <i>and</i> which key material to feed it. Three separate mistakes live here on purpose:</p>
 *
 * <ol>
 *   <li>{@code alg: "none"} is accepted with no signature check at all.</li>
 *   <li>{@code alg: "HS256"} is verified by HMAC-ing with {@code publicKey.getEncoded()} — the
 *       server's RSA <i>public</i> key, which by definition is not secret. Anyone who has it
 *       (i.e. everyone) can compute a valid HMAC and forge a token.</li>
 *   <li>The HMAC comparison uses {@code String.equals}, a non-constant-time comparison, on top of
 *       being reachable via the confused algorithm in the first place.</li>
 * </ol>
 */
final class VulnerableJwtVerifier {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String RSA_SIGNATURE_ALGORITHM = "SHA256withRSA";

    private final PublicKey publicKey;

    VulnerableJwtVerifier(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    Map<String, Object> verify(String token) {
        JwtToken parsed = JwtToken.parse(token);
        String alg = String.valueOf(parsed.header().get("alg"));

        return switch (alg) {
            // Bug 1: "none" is a legitimate JWS algorithm name (RFC 7518 §3.6) for *unsecured* JWTs.
            // A verifier that blindly honors whatever the token claims about itself will honor this too.
            case "none" -> parsed.payload();

            // Bug 2 + 3: HMAC-verify using the RSA public key's bytes as the HMAC secret, compared
            // with a non-constant-time String.equals.
            case "HS256" -> {
                byte[] expected = hmac(parsed.signingInput(), publicKey.getEncoded());
                String expectedB64 = Base64Url.encode(expected);
                if (!expectedB64.equals(parsed.signatureB64())) {
                    throw new JwtException("Rejected: HMAC signature mismatch");
                }
                yield parsed.payload();
            }

            case "RS256" -> {
                if (!verifyRsa(parsed.signingInput(), parsed.signature())) {
                    throw new JwtException("Rejected: RSA signature mismatch");
                }
                yield parsed.payload();
            }

            default -> throw new JwtException("Rejected: unsupported alg '" + alg + "'");
        };
    }

    private byte[] hmac(String data, byte[] key) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new JwtException("Failed to compute HMAC signature", e);
        }
    }

    private boolean verifyRsa(String data, byte[] signatureBytes) {
        try {
            Signature signature = Signature.getInstance(RSA_SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }
}
