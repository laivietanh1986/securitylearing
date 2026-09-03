package com.example.securitylearing.bench;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Standalone timing benchmark for BCrypt cost factors 4..15, run with:
 *   mvn exec:java@bcrypt-benchmark
 *
 * Not a JUnit test: some cost factors take seconds per hash, which does not belong
 * in the regular test suite. Prints a markdown table to stdout.
 */
public final class BCryptBenchmark {

    private static final String PASSWORD = "correct-horse-battery-staple";

    private BCryptBenchmark() {
    }

    public static void main(String[] args) {
        System.out.println("| cost | avg ms/hash | hashes/sec |");
        System.out.println("|------|-------------|------------|");

        for (int cost = 4; cost <= 15; cost++) {
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(cost);

            int warmup = cost >= 13 ? 1 : 2;
            int iterations = cost <= 10 ? 10 : (cost <= 12 ? 5 : 3);

            for (int i = 0; i < warmup; i++) {
                encoder.encode(PASSWORD);
            }

            long totalNanos = 0;
            for (int i = 0; i < iterations; i++) {
                long start = System.nanoTime();
                encoder.encode(PASSWORD);
                totalNanos += System.nanoTime() - start;
            }

            double avgMs = (totalNanos / (double) iterations) / 1_000_000.0;
            double hashesPerSec = 1000.0 / avgMs;

            System.out.printf("| %d | %.2f | %.2f |%n", cost, avgMs, hashesPerSec);
        }
    }
}
