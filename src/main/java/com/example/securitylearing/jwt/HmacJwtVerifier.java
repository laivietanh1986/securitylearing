package com.example.securitylearing.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * Part A.2/A.3 — hand-rolled HS256 verification, hardened against Part B's attacks:
 *
 * <ul>
 *   <li><b>alg:none (B.4)</b> — {@link #ALLOWED_ALGORITHMS} is a closed, server-side whitelist.
 *       The header's {@code alg} is only ever compared against it; it is never used to decide
 *       <i>how</i> to verify. A token whose header says {@code "alg":"none"} is rejected before
 *       any signature logic runs, and an empty signature segment is never treated as "no
 *       signature required".</li>
 *   <li><b>algorithm confusion (B.5)</b> — this class only knows how to do one thing: HMAC with
 *       the one {@code secret} it was constructed with. It has no code path that would ever
 *       treat an RSA key as an HMAC key, so pairing it with {@link RsaJwtVerifier} (which only
 *       accepts {@code RS256}) closes the hole that {@link VulnerableJwtVerifier} demonstrates.</li>
 *   <li><b>tampering (B.6)</b> — the signature is recomputed from the actual header/payload
 *       bytes and compared with {@link MessageDigest#isEqual}, so a single flipped bit anywhere
 *       in the payload changes the recomputed HMAC completely (avalanche effect) and fails.</li>
 *   <li><b>expiry (B.7)</b> — {@code exp} is required and checked against the clock with an
 *       explicit, small leeway for clock skew (default 0, i.e. no tolerance).</li>
 * </ul>
 *
 * <p><b>Why {@link MessageDigest#isEqual} and not {@code String.equals}/{@code Arrays.equals}:</b>
 * both of those short-circuit and return as soon as they find the first differing byte/char. That
 * makes the comparison time depend on <i>how many leading bytes were guessed correctly</i>, which
 * is a textbook timing side channel: an attacker who can measure response latency precisely enough
 * (locally, or even remotely with enough samples) can recover the correct signature one byte at a
 * time instead of needing to brute-force it all at once. {@code MessageDigest.isEqual} always walks
 * every byte of both arrays regardless of where they first differ, so the comparison takes the same
 * time whether the guess is completely wrong or off by one byte.</p>
 */
public final class HmacJwtVerifier {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final Set<String> ALLOWED_ALGORITHMS = Set.of("HS256");

    private final byte[] secret;
    private final String expectedIssuer;
    private final String expectedAudience;
    private final long leewaySeconds;
    private final Clock clock;

    private HmacJwtVerifier(Builder builder) {
        this.secret = builder.secret;
        this.expectedIssuer = builder.expectedIssuer;
        this.expectedAudience = builder.expectedAudience;
        this.leewaySeconds = builder.leewaySeconds;
        this.clock = builder.clock;
    }

    public static Builder builder(byte[] secret) {
        return new Builder(secret);
    }

    /** Returns the validated claim set, or throws {@link JwtException} describing why the token was rejected. */
    public Map<String, Object> verify(String token) {
        JwtToken parsed = JwtToken.parse(token);

        String alg = String.valueOf(parsed.header().get("alg"));
        if (!ALLOWED_ALGORITHMS.contains(alg)) {
            throw new JwtException("Rejected: alg '" + alg + "' is not in the server-side whitelist " + ALLOWED_ALGORITHMS);
        }

        byte[] expectedSignature = hmac(parsed.signingInput());
        if (!MessageDigest.isEqual(expectedSignature, parsed.signature())) {
            throw new JwtException("Rejected: signature mismatch");
        }

        validateClaims(parsed.payload());
        return parsed.payload();
    }

    private void validateClaims(Map<String, Object> payload) {
        long now = clock.instant().getEpochSecond();

        long exp = requireNumericClaim(payload, "exp");
        if (now - leewaySeconds >= exp) {
            throw new JwtException("Rejected: token expired at " + Instant.ofEpochSecond(exp));
        }

        Long iat = numericClaim(payload, "iat");
        if (iat != null && iat - leewaySeconds > now) {
            throw new JwtException("Rejected: 'iat' is in the future");
        }

        Long nbf = numericClaim(payload, "nbf");
        if (nbf != null && now + leewaySeconds < nbf) {
            throw new JwtException("Rejected: token not valid yet (nbf=" + Instant.ofEpochSecond(nbf) + ")");
        }

        if (expectedIssuer != null && !expectedIssuer.equals(payload.get("iss"))) {
            throw new JwtException("Rejected: unexpected issuer '" + payload.get("iss") + "'");
        }

        if (expectedAudience != null && !audienceMatches(payload.get("aud"), expectedAudience)) {
            throw new JwtException("Rejected: audience '" + payload.get("aud") + "' does not contain '" + expectedAudience + "'");
        }
    }

    private boolean audienceMatches(Object aud, String expected) {
        if (aud instanceof String single) {
            return expected.equals(single);
        }
        if (aud instanceof Collection<?> many) {
            return many.stream().anyMatch(expected::equals);
        }
        return false;
    }

    private long requireNumericClaim(Map<String, Object> payload, String name) {
        Long value = numericClaim(payload, name);
        if (value == null) {
            throw new JwtException("Rejected: missing required '" + name + "' claim");
        }
        return value;
    }

    private Long numericClaim(Map<String, Object> payload, String name) {
        Object value = payload.get(name);
        if (value == null) {
            return null;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        throw new JwtException("Rejected: claim '" + name + "' is not numeric");
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

    public static final class Builder {
        private final byte[] secret;
        private String expectedIssuer;
        private String expectedAudience;
        private long leewaySeconds = 0;
        private Clock clock = Clock.systemUTC();

        private Builder(byte[] secret) {
            if (secret == null || secret.length == 0) {
                throw new IllegalArgumentException("HMAC secret must not be empty");
            }
            this.secret = secret.clone();
        }

        public Builder expectedIssuer(String issuer) {
            this.expectedIssuer = issuer;
            return this;
        }

        public Builder expectedAudience(String audience) {
            this.expectedAudience = audience;
            return this;
        }

        /** Tolerance applied to exp/iat/nbf checks to absorb clock skew between issuer and verifier. */
        public Builder leewaySeconds(long leewaySeconds) {
            if (leewaySeconds < 0) {
                throw new IllegalArgumentException("leewaySeconds must not be negative");
            }
            this.leewaySeconds = leewaySeconds;
            return this;
        }

        /** Test seam — lets tests fix "now" instead of depending on the system clock. */
        public Builder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        public HmacJwtVerifier build() {
            return new HmacJwtVerifier(this);
        }
    }
}
