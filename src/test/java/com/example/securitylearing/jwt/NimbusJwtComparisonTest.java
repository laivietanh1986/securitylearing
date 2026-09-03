package com.example.securitylearing.jwt;

import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Part C — runs the exact same attacks from {@link HmacJwtVerifierTest} and
 * {@link AlgorithmConfusionAttackTest} against {@link NimbusJwtService}, to compare how a real
 * library defends against them versus the hand-rolled (fixed) implementation.
 *
 * <p>Nimbus's defenses are structural rather than a checklist a caller can forget:</p>
 * <ul>
 *   <li><b>alg:none</b> is not a valid JWS algorithm, so {@code SignedJWT.parse(...)} throws while
 *       still parsing the header — an unsecured token never becomes a {@code SignedJWT} at all
 *       (that concept is a separate type, {@code PlainJWT}).</li>
 *   <li><b>Algorithm confusion</b> is closed by binding the key to a verifier type:
 *       {@code MACVerifier} only implements HMAC and only advertises support for
 *       HS256/384/512 via {@code supportedJWSAlgorithms()}; {@code JWSObject.verify(...)} checks
 *       the token's header algorithm against that set before invoking the verifier, so an RS256
 *       (or forged-HS256-using-a-public-key) token is refused before any key material is touched.</li>
 * </ul>
 */
class NimbusJwtComparisonTest {

    private final byte[] secret = "correct-horse-battery-staple-super-secret-nimbus".getBytes(StandardCharsets.UTF_8);

    @Test
    void roundTrip_validToken_verifiesAndReturnsClaims() {
        Instant now = Instant.parse("2026-09-03T10:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);

        String token = NimbusJwtService.signHs256(secret, claims(now.plusSeconds(300)));
        Map<String, Object> claims = NimbusJwtService.verifyHs256(secret, token, 0, clock);

        assertThat(claims.get("sub")).isEqualTo("user-42");
    }

    @Test
    void rejectsAlgNone_atParseTime() {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "none");
        header.put("typ", "JWT");
        String headerB64 = Base64Url.encode(Json.toJson(header));
        String payloadB64 = Base64Url.encode(Json.toJson(claims(Instant.now().plusSeconds(60))));
        String forgedToken = headerB64 + "." + payloadB64 + ".";

        // Unlike the hand-rolled parser, nimbus refuses to even construct a SignedJWT from this input.
        assertThatThrownBy(() -> SignedJWT.parse(forgedToken))
                .isInstanceOf(java.text.ParseException.class);
    }

    @Test
    void algorithmConfusion_forgedHs256TokenUsingRsaPublicKey_isRejectedByAlgorithmBoundKeySelector() throws Exception {
        KeyPair serverRsaKeyPair = TestKeys.generateRsaKeyPair();
        byte[] publicKeyBytesKnownToAttacker = serverRsaKeyPair.getPublic().getEncoded();

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "HS256");
        header.put("typ", "JWT");
        String headerB64 = Base64Url.encode(Json.toJson(header));
        String payloadB64 = Base64Url.encode(Json.toJson(Map.of(
                "sub", "attacker",
                "role", "admin",
                "exp", Instant.now().plusSeconds(300).getEpochSecond())));
        String signingInput = headerB64 + "." + payloadB64;

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(publicKeyBytesKnownToAttacker, "HmacSHA256"));
        String forgedSignature = Base64Url.encode(mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)));
        String forgedToken = signingInput + "." + forgedSignature;

        // The idiomatic nimbus setup: the server registers its RSA key under RS256 and lets a
        // JWSVerificationKeySelector pick the key by (algorithm, key type). Note this key source
        // never holds a "secret" at all - only an RSAKey - so there is no byte array anywhere for
        // an HS256 header to be confused into using. This is the structural fix, not a runtime check.
        com.nimbusds.jose.jwk.RSAKey rsaJwk = new com.nimbusds.jose.jwk.RSAKey.Builder(
                (java.security.interfaces.RSAPublicKey) serverRsaKeyPair.getPublic()).build();
        com.nimbusds.jose.jwk.source.ImmutableJWKSet<com.nimbusds.jose.proc.SecurityContext> jwkSource =
                new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(new com.nimbusds.jose.jwk.JWKSet(rsaJwk));

        com.nimbusds.jwt.proc.DefaultJWTProcessor<com.nimbusds.jose.proc.SecurityContext> processor =
                new com.nimbusds.jwt.proc.DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new com.nimbusds.jose.proc.JWSVerificationKeySelector<>(
                com.nimbusds.jose.JWSAlgorithm.RS256, jwkSource));

        assertThatThrownBy(() -> processor.process(forgedToken, null))
                .isInstanceOf(Exception.class);

        // Contrast: a naive verifier that (like VulnerableJwtVerifier) trusts the header and hands
        // the raw public key bytes to a MACVerifier reproduces the vulnerability even with nimbus -
        // the library only saves you when you use its algorithm-bound key selection APIs.
        SignedJWT jwt = SignedJWT.parse(forgedToken);
        assertThat(jwt.verify(new MACVerifier(publicKeyBytesKnownToAttacker))).isTrue();
    }

    @Test
    void rejectsBitFlippedPayload() {
        String token = NimbusJwtService.signHs256(secret, claims(Instant.now().plusSeconds(300)));
        String[] parts = token.split("\\.");
        byte[] payloadBytes = Base64Url.decode(parts[1]);
        String payloadJson = new String(payloadBytes, StandardCharsets.UTF_8);
        int flipIndex = payloadJson.indexOf("42");
        payloadBytes[flipIndex] ^= 0x01;
        String tamperedToken = parts[0] + "." + Base64Url.encode(payloadBytes) + "." + parts[2];

        assertThatThrownBy(() -> NimbusJwtService.verifyHs256(secret, tamperedToken, 0, Clock.systemUTC()))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsTokenExpiredOneSecondAgo() {
        Instant now = Instant.parse("2026-09-03T10:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);

        String token = NimbusJwtService.signHs256(secret, claims(now.minusSeconds(1)));

        assertThatThrownBy(() -> NimbusJwtService.verifyHs256(secret, token, 0, clock))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void rsa_roundTrip_andRejectsForeignKey() {
        KeyPair serverKeyPair = TestKeys.generateRsaKeyPair();
        KeyPair attackerKeyPair = TestKeys.generateRsaKeyPair();

        String token = NimbusJwtService.signRs256(serverKeyPair.getPrivate(), claims(Instant.now().plusSeconds(300)));
        Map<String, Object> claims = NimbusJwtService.verifyRs256((RSAPublicKey) serverKeyPair.getPublic(), token, 0, Clock.systemUTC());
        assertThat(claims.get("sub")).isEqualTo("user-42");

        String tokenFromAttacker = NimbusJwtService.signRs256(attackerKeyPair.getPrivate(), claims(Instant.now().plusSeconds(300)));
        assertThatThrownBy(() -> NimbusJwtService.verifyRs256((RSAPublicKey) serverKeyPair.getPublic(), tokenFromAttacker, 0, Clock.systemUTC()))
                .isInstanceOf(JwtException.class);
    }

    private Map<String, Object> claims(Instant exp) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "user-42");
        claims.put("exp", exp.getEpochSecond());
        return claims;
    }
}
