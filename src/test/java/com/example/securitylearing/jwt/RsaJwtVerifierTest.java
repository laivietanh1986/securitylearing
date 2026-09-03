package com.example.securitylearing.jwt;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RsaJwtVerifierTest {

    @Test
    void roundTrip_validToken_verifiesAndReturnsClaims() {
        KeyPair keyPair = TestKeys.generateRsaKeyPair();
        RsaJwtSigner signer = new RsaJwtSigner(keyPair.getPrivate());
        String token = signer.sign(claims(Instant.now().plusSeconds(300)));

        RsaJwtVerifier verifier = RsaJwtVerifier.of(keyPair.getPublic());
        assertThat(verifier.verify(token).get("sub")).isEqualTo("user-42");
    }

    @Test
    void rejectsTokenSignedByADifferentKeyPair() {
        KeyPair serverKeyPair = TestKeys.generateRsaKeyPair();
        KeyPair attackerKeyPair = TestKeys.generateRsaKeyPair();

        RsaJwtSigner attackerSigner = new RsaJwtSigner(attackerKeyPair.getPrivate());
        String tokenSignedByAttacker = attackerSigner.sign(claims(Instant.now().plusSeconds(300)));

        RsaJwtVerifier verifier = RsaJwtVerifier.of(serverKeyPair.getPublic());
        assertThatThrownBy(() -> verifier.verify(tokenSignedByAttacker))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("signature mismatch");
    }

    @Test
    void rejectsExpiredToken() {
        Instant now = Instant.parse("2026-09-03T10:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        KeyPair keyPair = TestKeys.generateRsaKeyPair();

        RsaJwtSigner signer = new RsaJwtSigner(keyPair.getPrivate());
        String token = signer.sign(claims(now.minusSeconds(1)));

        RsaJwtVerifier verifier = RsaJwtVerifier.of(keyPair.getPublic(), 0, clock);
        assertThatThrownBy(() -> verifier.verify(token))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("expired");
    }

    private Map<String, Object> claims(Instant exp) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "user-42");
        claims.put("exp", exp.getEpochSecond());
        return claims;
    }
}
