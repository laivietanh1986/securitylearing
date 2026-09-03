package com.example.securitylearing.jwt;

import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * Part B.5 fix — the RS256 counterpart to {@link HmacJwtVerifier}. Like it, this verifier hardcodes
 * its own algorithm whitelist ({@code RS256} only) and its own key ({@code publicKey}, fixed at
 * construction). It never reads {@code alg} from the token to decide which key or which crypto
 * primitive to use — that decision is fixed by which verifier instance the server chose to call.
 * That is precisely what {@link VulnerableJwtVerifier} gets wrong.
 */
public final class RsaJwtVerifier {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final Set<String> ALLOWED_ALGORITHMS = Set.of("RS256");

    private final PublicKey publicKey;
    private final long leewaySeconds;
    private final Clock clock;

    private RsaJwtVerifier(PublicKey publicKey, long leewaySeconds, Clock clock) {
        this.publicKey = publicKey;
        this.leewaySeconds = leewaySeconds;
        this.clock = clock;
    }

    public static RsaJwtVerifier of(PublicKey publicKey) {
        return new RsaJwtVerifier(publicKey, 0, Clock.systemUTC());
    }

    public static RsaJwtVerifier of(PublicKey publicKey, long leewaySeconds, Clock clock) {
        return new RsaJwtVerifier(publicKey, leewaySeconds, clock);
    }

    public Map<String, Object> verify(String token) {
        JwtToken parsed = JwtToken.parse(token);

        String alg = String.valueOf(parsed.header().get("alg"));
        if (!ALLOWED_ALGORITHMS.contains(alg)) {
            throw new JwtException("Rejected: alg '" + alg + "' is not in the server-side whitelist " + ALLOWED_ALGORITHMS);
        }

        if (!verifyRsa(parsed.signingInput(), parsed.signature())) {
            throw new JwtException("Rejected: signature mismatch");
        }

        Object expClaim = parsed.payload().get("exp");
        if (expClaim instanceof Number expNumber) {
            long now = clock.instant().getEpochSecond();
            long exp = expNumber.longValue();
            if (now - leewaySeconds >= exp) {
                throw new JwtException("Rejected: token expired at " + Instant.ofEpochSecond(exp));
            }
        } else {
            throw new JwtException("Rejected: missing required 'exp' claim");
        }

        return parsed.payload();
    }

    private boolean verifyRsa(String data, byte[] signatureBytes) {
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            // A malformed/foreign-format signature fails verification, it is not a server error.
            return false;
        }
    }
}
