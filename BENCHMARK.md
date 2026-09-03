# Password hashing benchmark

Real numbers, captured by actually running the benchmarks in this repo:

```
mvn exec:java@bcrypt-benchmark
mvn exec:java@argon2-benchmark
```

Environment: single JVM thread, one measurement pass per row (warmup discarded), this
development machine (results vary by hardware — re-run before trusting these numbers on
different hardware).

## BCrypt, cost 4 → 15

| cost | avg ms/hash (measured, this CPU) | defender hashes/sec (1 core) | est. attacker attempts/sec (1 GPU)* |
|------|-----------------------------------|-------------------------------|--------------------------------------|
| 4  | 2.34    | 427.91 | ~300,000 |
| 5  | 3.52    | 283.90 | ~150,000 |
| 6  | 6.03    | 165.81 | ~75,000  |
| 7  | 10.71   | 93.40  | ~37,500  |
| 8  | 16.55   | 60.41  | ~18,750  |
| 9  | 34.95   | 28.61  | ~9,375   |
| 10 | 68.50   | 14.60  | ~4,688   |
| 11 | 153.98  | 6.49   | ~2,344   |
| 12 | 331.64  | 3.02   | ~1,172   |
| 13 | 578.73  | 1.73   | ~586     |
| 14 | 1189.56 | 0.84   | ~293     |
| 15 | 2695.97 | 0.37   | ~146     |

\* **Methodology, not a measurement**: we don't have GPU hardware to benchmark against.
This column is derived, not measured: publicly published hashcat-style benchmarks put a
modern high-end consumer GPU (e.g. RTX 4090 class) at roughly 100–200 kH/s against
`bcrypt` cost 5 — bcrypt resists GPU parallelization far better than fast hashes like
MD5/SHA-1 because its Blowfish key schedule needs random-access memory reads that don't
vectorize well. We took 150,000 H/s at cost 5 as an illustrative baseline and applied
bcrypt's own cost-doubling property (`rate(cost) = rate(5) / 2^(cost-5)`) to the other
rows. Treat this column as order-of-magnitude, not exact — and remember an attacker can
run many GPUs in parallel, so multiply by fleet size for a real capacity estimate.

## Argon2id, 3 parameter sets

| parameter set | memory | iterations | parallelism | avg ms/hash (measured) | hashes/sec (1 core) |
|---|---|---|---|---|---|
| A — high memory, 1 pass    | 47104 KB (46 MiB) | 1 | 1 | 63.64 | 15.71 |
| B — OWASP balanced default | 19456 KB (19 MiB) | 2 | 1 | 35.51 | 28.16 |
| C — low memory, more passes| 12288 KB (12 MiB) | 3 | 1 | 35.46 | 28.20 |

**Attacker/GPU estimate for Argon2id**: qualitative, not a number I'll stand behind with
the same confidence as the bcrypt column. Argon2's memory-hardness means each parallel
guess needs its own private memory block (12–46 MiB here) rather than a few KB that fits
in GPU cache — so GPU throughput is bottlenecked by *memory bandwidth ÷ memory-per-guess*,
not raw compute. Published hashcat Argon2 benchmarks at comparable memory settings sit
roughly **one to two orders of magnitude below** the equivalent bcrypt-cost attacker rate
above (rough illustrative range: tens to a couple hundred H/s per GPU for set B/C, vs.
~1,000+ H/s for a bcrypt cost that costs the defender the same wall-clock time). That gap
is the entire point of choosing a memory-hard function over bcrypt for new systems.

## Chosen cost: BCrypt strength **12** (`SecurityConfig.BCRYPT_COST`)

- Measured 331.64 ms/hash on this machine — inside the commonly cited "≥250 ms, ideally
  under ~500 ms–1 s" budget for an interactive login endpoint (OWASP's guidance is "as
  high as the server can tolerate", typically capped by acceptable login latency).
- Cost 13 (578 ms) starts to noticeably affect perceived login speed and roughly halves
  a single server's peak login throughput again for comparatively small defensive gain;
  cost 11 (154 ms) is cheap enough that it stops being a meaningful deterrent against a
  well-resourced offline attacker without buying much UX headroom back.
- At cost 12, the GPU-estimate column above puts a single modern GPU at roughly
  ~1,000 guesses/sec offline — enough to grind through a small curated dictionary in
  seconds, but not enough to brute-force a password with real entropy in any practical
  timeframe. **This is the honest caveat**: BCrypt cost alone does not stop dictionary
  attacks against weak/reused passwords — that needs a password policy, breach-list
  checking, and rate-limiting/lockout on the endpoint itself, none of which are in scope
  here.
- If starting a new system rather than being bcrypt-compatible, parameter set **B**
  (m=19456 KB, t=2, p=1 — Spring Security's own `defaultsForSpringSecurity_v5_8()`
  preset) is the better choice over BCrypt: comparable ~36 ms defender cost, but the
  GPU-attacker gap above is roughly 10-20x wider thanks to memory-hardness.
