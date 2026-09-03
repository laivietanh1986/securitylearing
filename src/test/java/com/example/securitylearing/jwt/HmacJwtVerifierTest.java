package com.example.securitylearing.jwt;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Part A round trip plus the Part B attacks (4, 6, 7) run against the hardened
 * {@link HmacJwtVerifier} — every attack here must be rejected.
 */
class HmacJwtVerifierTest {

    private final byte[] secret = "correct-horse-battery-staple-super-secret".getBytes(StandardCharsets.UTF_8);

    @Test
    void roundTrip_validToken_verifiesAndReturnsClaims() {
        Instant now = Instant.parse("2026-09-03T10:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);

        HmacJwtSigner signer = new HmacJwtSigner(secret);
        String token = signer.sign(claims(now.plusSeconds(300), now, "auth-service", "billing-api"));

        HmacJwtVerifier verifier = HmacJwtVerifier.builder(secret)
                .clock(clock)
                .expectedIssuer("auth-service")
                .expectedAudience("billing-api")
                .build();

        Map<String, Object> claims = verifier.verify(token);
        assertThat(claims.get("sub")).isEqualTo("user-42");
    }

    @Test
    void rejectsAlgNone() {
        Instant now = Instant.now();
        // Forge a token with an unsigned "none" header and an empty signature segment.
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "none");
        header.put("typ", "JWT");
        String headerB64 = Base64Url.encode(Json.toJson(header));
        String payloadB64 = Base64Url.encode(Json.toJson(claims(now.plusSeconds(60), now, null, null)));
        String forgedToken = headerB64 + "." + payloadB64 + ".";

        HmacJwtVerifier verifier = HmacJwtVerifier.builder(secret).build();

        assertThatThrownBy(() -> verifier.verify(forgedToken))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("whitelist");
    }

    @Test
    void rejectsBitFlippedPayload() {
        Instant now = Instant.now();
        HmacJwtSigner signer = new HmacJwtSigner(secret);
        String token = signer.sign(claims(now.plusSeconds(300), now, null, null));

        String[] parts = token.split("\\.");
        byte[] payloadBytes = Base64Url.decode(parts[1]);
        // Flip the low bit of a digit inside "user-42" ('4' -> '5') so the JSON stays syntactically
        // valid and we exercise the signature check itself, not the JSON parser.
        String payloadJson = new String(payloadBytes, StandardCharsets.UTF_8);
        int flipIndex = payloadJson.indexOf("42");
        payloadBytes[flipIndex] ^= 0x01;
        String tamperedToken = parts[0] + "." + Base64Url.encode(payloadBytes) + "." + parts[2];

        HmacJwtVerifier verifier = HmacJwtVerifier.builder(secret).build();

        assertThatThrownBy(() -> verifier.verify(tamperedToken))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("signature mismatch");
    }

    @Test
    void rejectsTokenExpiredOneSecondAgo() {
        Instant now = Instant.parse("2026-09-03T10:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);

        HmacJwtSigner signer = new HmacJwtSigner(secret);
        String token = signer.sign(claims(now.minusSeconds(1), now.minusSeconds(300), null, null));

        HmacJwtVerifier verifier = HmacJwtVerifier.builder(secret).clock(clock).build();

        assertThatThrownBy(() -> verifier.verify(token))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void leewayAbsorbsSmallClockSkewButNotLargeExpiry() {
        Instant now = Instant.parse("2026-09-03T10:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);

        HmacJwtSigner signer = new HmacJwtSigner(secret);
        String tokenExpiredOneSecondAgo = signer.sign(claims(now.minusSeconds(1), now.minusSeconds(300), null, null));

        HmacJwtVerifier lenientVerifier = HmacJwtVerifier.builder(secret).clock(clock).leewaySeconds(5).build();
        assertThat(lenientVerifier.verify(tokenExpiredOneSecondAgo)).isNotNull();

        String tokenExpiredTenSecondsAgo = signer.sign(claims(now.minusSeconds(10), now.minusSeconds(300), null, null));
        assertThatThrownBy(() -> lenientVerifier.verify(tokenExpiredTenSecondsAgo))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void rejectsWrongIssuerAndAudience() {
        Instant now = Instant.now();
        HmacJwtSigner signer = new HmacJwtSigner(secret);
        String token = signer.sign(claims(now.plusSeconds(60), now, "auth-service", "billing-api"));

        HmacJwtVerifier verifier = HmacJwtVerifier.builder(secret).expectedIssuer("some-other-issuer").build();
        assertThatThrownBy(() -> verifier.verify(token))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("issuer");

        HmacJwtVerifier audienceVerifier = HmacJwtVerifier.builder(secret).expectedAudience("some-other-api").build();
        assertThatThrownBy(() -> audienceVerifier.verify(token))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("audience");
    }

    private Map<String, Object> claims(Instant exp, Instant iat, String iss, String aud) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "user-42");
        claims.put("exp", exp.getEpochSecond());
        claims.put("iat", iat.getEpochSecond());
        if (iss != null) {
            claims.put("iss", iss);
        }
        if (aud != null) {
            claims.put("aud", aud);
        }
        return claims;
    }
}
