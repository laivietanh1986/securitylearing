package com.example.securitylearing.jwt;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Part B.4 and B.5: proves {@link VulnerableJwtVerifier} is exploitable, then proves the same
 * forged tokens are rejected once the server switches to {@link RsaJwtVerifier}/{@link HmacJwtVerifier}.
 *
 * <p>The attacker in the algorithm-confusion scenario never has the server's RSA private key.
 * All they have is the RSA <i>public</i> key — which is public by design (e.g. published at a
 * JWKS endpoint, or embedded in a client app). If the verifier's HS256 branch treats that public
 * key's bytes as an HMAC secret, the attacker can compute a valid HMAC themselves and forge
 * arbitrary claims.</p>
 */
class AlgorithmConfusionAttackTest {

    @Test
    void vulnerableVerifier_acceptsAlgNone_noSignatureRequired() {
        VulnerableJwtVerifier vulnerable = new VulnerableJwtVerifier(TestKeys.generateRsaKeyPair().getPublic());

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "none");
        header.put("typ", "JWT");
        String headerB64 = Base64Url.encode(Json.toJson(header));
        String payloadB64 = Base64Url.encode(Json.toJson(Map.of("sub", "attacker", "role", "admin")));
        String forgedToken = headerB64 + "." + payloadB64 + ".";

        // No exception: the vulnerable verifier honors the attacker's own claim that no signature is needed.
        Map<String, Object> claims = vulnerable.verify(forgedToken);
        assertThat(claims.get("role")).isEqualTo("admin");
    }

    @Test
    void algorithmConfusion_forgedHs256Token_isAcceptedByVulnerableVerifier_thenRejectedByHardenedRsaVerifier() throws Exception {
        KeyPair serverRsaKeyPair = TestKeys.generateRsaKeyPair();

        // The attacker only ever touches the PUBLIC key - exactly what a real client/JWKS endpoint would expose.
        byte[] publicKeyBytesKnownToAttacker = serverRsaKeyPair.getPublic().getEncoded();

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "HS256"); // attacker picks the algorithm, not the server
        header.put("typ", "JWT");
        String headerB64 = Base64Url.encode(Json.toJson(header));
        String payloadB64 = Base64Url.encode(Json.toJson(Map.of(
                "sub", "attacker",
                "role", "admin",
                "exp", Instant.now().plusSeconds(300).getEpochSecond())));
        String signingInput = headerB64 + "." + payloadB64;

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(publicKeyBytesKnownToAttacker, "HmacSHA256"));
        String forgedSignature = Base64Url.encode(mac.doFinal(signingInput.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        String forgedToken = signingInput + "." + forgedSignature;

        // Vulnerability: the server's "generic" verifier treats its own RSA public key as an HMAC secret.
        VulnerableJwtVerifier vulnerable = new VulnerableJwtVerifier(serverRsaKeyPair.getPublic());
        Map<String, Object> forgedClaims = vulnerable.verify(forgedToken);
        assertThat(forgedClaims.get("role")).isEqualTo("admin");

        // Fix: a verifier that hardcodes its algorithm (RS256 only, real RSA signature check) rejects it outright.
        RsaJwtVerifier hardened = RsaJwtVerifier.of(serverRsaKeyPair.getPublic());
        assertThatThrownBy(() -> hardened.verify(forgedToken))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("whitelist");
    }
}
