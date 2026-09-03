package com.example.securitylearing.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

/**
 * Part C — the same two operations as {@link HmacJwtSigner}/{@link HmacJwtVerifier} and
 * {@link RsaJwtSigner}/{@link RsaJwtVerifier}, implemented with nimbus-jose-jwt instead of by hand.
 * See {@code NimbusJwtComparisonTest} for how it behaves against the exact same Part B attacks.
 */
public final class NimbusJwtService {

    private NimbusJwtService() {
    }

    public static String signHs256(byte[] secret, Map<String, Object> claims) {
        try {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
            claims.forEach(builder::claim);
            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), builder.build());
            jwt.sign(new MACSigner(secret));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new JwtException("Failed to sign JWT with nimbus", e);
        }
    }

    public static String signRs256(PrivateKey privateKey, Map<String, Object> claims) {
        try {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
            claims.forEach(builder::claim);
            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), builder.build());
            jwt.sign(new RSASSASigner(privateKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new JwtException("Failed to sign JWT with nimbus", e);
        }
    }

    /**
     * Verifies an HS256 token. Nimbus enforces the algorithm whitelist structurally: a
     * {@link MACVerifier} only ever runs HMAC and only ever accepts HS256/384/512 headers
     * (see {@link MACVerifier#supportedJWSAlgorithms()}); {@link SignedJWT#verify} refuses to
     * call it for any other header algorithm. There is no code path, correct or buggy, that
     * would let this method use the secret as anything other than an HMAC key.
     */
    public static Map<String, Object> verifyHs256(byte[] secret, String token, long leewaySeconds, Clock clock) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!jwt.verify(new MACVerifier(secret))) {
                throw new JwtException("Rejected: signature mismatch");
            }
            return validateClaims(jwt.getJWTClaimsSet(), leewaySeconds, clock);
        } catch (ParseException | JOSEException e) {
            throw new JwtException("Rejected: " + e.getMessage(), e);
        }
    }

    /** Same structural guarantee as {@link #verifyHs256}, but bound to RSA signature verification and a public key. */
    public static Map<String, Object> verifyRs256(RSAPublicKey publicKey, String token, long leewaySeconds, Clock clock) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!jwt.verify(new RSASSAVerifier(publicKey))) {
                throw new JwtException("Rejected: signature mismatch");
            }
            return validateClaims(jwt.getJWTClaimsSet(), leewaySeconds, clock);
        } catch (ParseException | JOSEException e) {
            throw new JwtException("Rejected: " + e.getMessage(), e);
        }
    }

    private static Map<String, Object> validateClaims(JWTClaimsSet claims, long leewaySeconds, Clock clock) {
        Date exp = claims.getExpirationTime();
        if (exp == null) {
            throw new JwtException("Rejected: missing required 'exp' claim");
        }
        Instant now = clock.instant();
        if (now.minusSeconds(leewaySeconds).isAfter(exp.toInstant()) || now.minusSeconds(leewaySeconds).equals(exp.toInstant())) {
            throw new JwtException("Rejected: token expired at " + exp.toInstant());
        }
        return claims.getClaims();
    }
}
