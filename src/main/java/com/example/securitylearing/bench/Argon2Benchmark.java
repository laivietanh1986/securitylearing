package com.example.securitylearing.bench;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

/**
 * Standalone timing benchmark for 3 Argon2id parameter sets (OWASP-cited), run with:
 *   mvn exec:java@argon2-benchmark
 */
public final class Argon2Benchmark {

    private static final String PASSWORD = "correct-horse-battery-staple";
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;

    private record ParamSet(String name, int memoryKb, int iterations, int parallelism) {
    }

    private static final ParamSet[] PARAM_SETS = {
            new ParamSet("A: high memory, 1 pass   (m=47104 KB, t=1, p=1)", 47104, 1, 1),
            new ParamSet("B: OWASP default balance (m=19456 KB, t=2, p=1)", 19456, 2, 1),
            new ParamSet("C: low memory, more passes(m=12288 KB, t=3, p=1)", 12288, 3, 1),
    };

    private Argon2Benchmark() {
    }

    public static void main(String[] args) {
        System.out.println("| parameter set | avg ms/hash | hashes/sec |");
        System.out.println("|---------------|-------------|------------|");

        for (ParamSet params : PARAM_SETS) {
            Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(
                    SALT_LENGTH, HASH_LENGTH, params.parallelism(), params.memoryKb(), params.iterations());

            int warmup = 1;
            int iterations = 5;

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

            System.out.printf("| %s | %.2f | %.2f |%n", params.name(), avgMs, hashesPerSec);
        }
    }
}
