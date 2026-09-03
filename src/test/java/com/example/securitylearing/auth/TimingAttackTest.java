package com.example.securitylearing.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.securitylearing.user.User;
import com.example.securitylearing.user.UserRepository;

/**
 * Without a dummy-hash comparison, /login is faster when the email doesn't exist at
 * all (no password hashing happens) than when it exists but the password is wrong
 * (a full BCrypt comparison runs) — an attacker can use that latency gap to enumerate
 * valid accounts. AuthService.login always calls passwordEncoder.matches() against
 * *some* hash of equal cost regardless of whether the email was found, closing the gap.
 *
 * This test measures p50/p99 latency for both branches (email exists vs. doesn't) and
 * asserts the gap stays under 5ms. UserRepository is mocked so DB/H2 I/O jitter doesn't
 * drown out the signal being tested, and a low BCrypt cost keeps the suite fast while
 * still exercising a real hash comparison of non-trivial, matched cost on both branches.
 */
class TimingAttackTest {

    private static final int WARMUP_ITERATIONS = 50;
    private static final int MEASURED_ITERATIONS = 200;
    private static final double MAX_ALLOWED_GAP_MS = 5.0;

    private static final String EXISTING_EMAIL = "existing@example.com";
    private static final String MISSING_EMAIL = "missing@example.com";

    @Test
    void loginLatencyForExistingVsMissingEmailStaysWithin5ms() {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(6);

        User existingUser = new User(EXISTING_EMAIL, passwordEncoder.encode("real-password"));
        UserRepository userRepository = mock(UserRepository.class);
        when(userRepository.findByEmail(eq(EXISTING_EMAIL))).thenReturn(Optional.of(existingUser));
        when(userRepository.findByEmail(eq(MISSING_EMAIL))).thenReturn(Optional.empty());

        AuthService authService = new AuthService(userRepository, passwordEncoder);

        // Warm up the JVM/JIT on both code paths before measuring either one.
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            authService.login(EXISTING_EMAIL, "wrong-password");
            authService.login(MISSING_EMAIL, "wrong-password");
        }

        double[] existingMs = new double[MEASURED_ITERATIONS];
        double[] missingMs = new double[MEASURED_ITERATIONS];

        // Interleaved so any drift over the run (GC, frequency scaling) hits both
        // branches evenly instead of biasing whichever branch runs second.
        for (int i = 0; i < MEASURED_ITERATIONS; i++) {
            existingMs[i] = timeLoginMs(authService, EXISTING_EMAIL, "wrong-password");
            missingMs[i] = timeLoginMs(authService, MISSING_EMAIL, "wrong-password");
        }

        double existingP50 = percentile(existingMs, 0.50);
        double existingP99 = percentile(existingMs, 0.99);
        double missingP50 = percentile(missingMs, 0.50);
        double missingP99 = percentile(missingMs, 0.99);

        double p50Gap = Math.abs(existingP50 - missingP50);
        double p99Gap = Math.abs(existingP99 - missingP99);

        System.out.printf(
                "existing email -> p50=%.3fms p99=%.3fms | missing email -> p50=%.3fms p99=%.3fms | p50 gap=%.3fms p99 gap=%.3fms%n",
                existingP50, existingP99, missingP50, missingP99, p50Gap, p99Gap);

        assertThat(p50Gap).as("p50 latency gap between existing and missing email").isLessThan(MAX_ALLOWED_GAP_MS);
        assertThat(p99Gap).as("p99 latency gap between existing and missing email").isLessThan(MAX_ALLOWED_GAP_MS);
    }

    private static double timeLoginMs(AuthService authService, String email, String password) {
        long start = System.nanoTime();
        authService.login(email, password);
        long elapsedNanos = System.nanoTime() - start;
        return elapsedNanos / 1_000_000.0;
    }

    private static double percentile(double[] valuesMs, double p) {
        double[] sorted = valuesMs.clone();
        Arrays.sort(sorted);
        int index = (int) Math.ceil(p * sorted.length) - 1;
        index = Math.max(0, Math.min(sorted.length - 1, index));
        return sorted[index];
    }
}
