package com.example.securitylearing.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.securitylearing.config.SecurityConfig;
import com.example.securitylearing.user.User;
import com.example.securitylearing.user.UserRepository;

/**
 * Simulates the legacy-system scenario: a user row stored with an {MD5} hash (as
 * LegacyUserSeeder would create) is transparently migrated to {bcrypt} on the very
 * login that first succeeds against it — no forced password reset.
 */
@SuppressWarnings("deprecation")
class LegacyPasswordMigrationTest {

    private static final String RAW_PASSWORD = "legacyPass123";

    private PasswordEncoder buildDelegatingEncoder() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put(SecurityConfig.BCRYPT_ID, new BCryptPasswordEncoder(4));
        encoders.put(SecurityConfig.MD5_ID, new MessageDigestPasswordEncoder("MD5"));
        return new DelegatingPasswordEncoder(SecurityConfig.BCRYPT_ID, encoders);
    }

    @Test
    void loginMigratesLegacyMd5HashToBcryptWithoutPasswordReset() {
        PasswordEncoder passwordEncoder = buildDelegatingEncoder();
        MessageDigestPasswordEncoder md5Encoder = new MessageDigestPasswordEncoder("MD5");
        String legacyHash = "{" + SecurityConfig.MD5_ID + "}" + md5Encoder.encode(RAW_PASSWORD);

        User user = new User("legacy@example.com", legacyHash);
        UserRepository userRepository = mock(UserRepository.class);
        when(userRepository.findByEmail(eq("legacy@example.com"))).thenReturn(Optional.of(user));

        AuthService authService = new AuthService(userRepository, passwordEncoder);

        assertThat(user.getPasswordHash()).startsWith("{MD5}");

        AuthService.LoginResult firstLogin = authService.login("legacy@example.com", RAW_PASSWORD);

        assertThat(firstLogin).isEqualTo(AuthService.LoginResult.OK);
        assertThat(user.getPasswordHash()).startsWith("{bcrypt}");
        assertThat(user.getPasswordHash()).isNotEqualTo(legacyHash);

        // Same raw password still works, transparently, now against the bcrypt hash.
        AuthService.LoginResult secondLogin = authService.login("legacy@example.com", RAW_PASSWORD);
        assertThat(secondLogin).isEqualTo(AuthService.LoginResult.OK);
    }

    @Test
    void wrongPasswordAgainstLegacyHashDoesNotMigrate() {
        PasswordEncoder passwordEncoder = buildDelegatingEncoder();
        MessageDigestPasswordEncoder md5Encoder = new MessageDigestPasswordEncoder("MD5");
        String legacyHash = "{" + SecurityConfig.MD5_ID + "}" + md5Encoder.encode(RAW_PASSWORD);

        User user = new User("legacy@example.com", legacyHash);
        UserRepository userRepository = mock(UserRepository.class);
        when(userRepository.findByEmail(any())).thenReturn(Optional.of(user));

        AuthService authService = new AuthService(userRepository, passwordEncoder);

        AuthService.LoginResult result = authService.login("legacy@example.com", "wrong-password");

        assertThat(result).isEqualTo(AuthService.LoginResult.INVALID_CREDENTIALS);
        assertThat(user.getPasswordHash()).isEqualTo(legacyHash);
    }
}
