# PSAR cohort scaling

Source of truth for issue #684's storage and aggregate-time numbers
across the (K × N) cross-product. Regenerate with:

```bash
scripts/psar-scaling.sh --include-stretch
```

Numbers below are from one run on the hardware listed below. Each
configuration runs the full PSAR pipeline (`psar-demo`): K-user
boarding → N epochs → per-user signature verification.

## Hardware context

| Field     | Value                                       |
|-----------|---------------------------------------------|
| CPU       | Apple M3 Max                                |
| Cores     | 14 (10 performance + 4 efficiency)          |
| Memory    | 36 GB                                       |
| OS        | macOS 26.3.1 (Darwin 25.3.0)                |
| Toolchain | rustc 1.95.0 (release profile, lto = false) |

## Wall-clock at four configurations

| K       | N   | boarding_ms | epoch_ms_avg | total_sigs | all_verify | wall_clock_ms |
|---------|-----|-------------|--------------|------------|------------|----------------|
| 100     | 12  | 493         | 22.2         | 1 200      | true       | 830            |
| 1 000   | 12  | 5 644       | 227.7        | 12 000     | true       | 9 017          |
| 1 000   | 50  | 20 370      | 228.7        | 50 000     | true       | 34 389         |
| 10 000  | 12  | 141 986     | 2 291.7      | 120 000    | true       | 175 818        |

**Lead row** (★) for the paper: **K=1000, N=12** — production-shape
cohort that completes in under 10 s wall-clock end-to-end.

### Observations

- **Per-epoch cost is K-linear, N-independent.** At K=1000, the
  per-epoch median is 227.7 ms regardless of horizon (matches the
  isolated bench in `docs/benchmarks/psar-epoch.md`).
- **Boarding is K-linear up to K=1000.** From K=100 to K=1000 the
  ratio is 5644 / 493 ≈ 11.4× for a 10× user-count increase —
  consistent with linear plus a fixed setup cost (`Setup::run`,
  slot-tree construction).
- **K=10000 is super-linear in boarding.** 142 s vs 5.64 s × 10 ≈
  56 s expected → ~2.5× over the linear extrapolation. Likely
  causes: heap-allocator pressure on the K-vector pre-signed
  artifacts and L2/L3 cache thrash during the per-user `user_board`
  Λ-verify pass. Per-epoch processing remains linear (2.29 s vs
  228 ms × 10 = 2.28 s expected). Profile-guided cleanup is a
  follow-up; the K=10000 cohort still completes in ~3 minutes.

### Per-user amortised cost

| K       | N   | boarding µs/user | epoch µs/user/epoch |
|---------|-----|-------------------|---------------------|
| 100     | 12  | 4 930             | 222                 |
| 1 000   | 12  | 5 644             | 228                 |
| 1 000   | 50  | 20 370            | 229                 |
| 10 000  | 12  | 14 199            | 229                 |

Per-user epoch cost is **226–229 µs** stable across all configs.
Per-user boarding cost stays in the **5–6 ms** band up to K=1000;
K=10000's 14 ms/user reflects the super-linear regime above.

## Storage per cohort

Storage analytics are derived from the in-memory layout of
`dark_psar::ActiveCohort` and the wire formulas published in
`docs/benchmarks/von-primitives.md`. These are tight lower bounds;
allocator slack and `Vec` capacity overhead typically add 20–30 %.

### Component formulas

| Component                                       | Formula (bytes)         | Notes                                   |
|-------------------------------------------------|-------------------------|-----------------------------------------|
| `RetainedScalars` (operator-only)               | `64 · N`                | `2N` × `SecretKey` (32 B each)          |
| `PublishedSchedule`                             | `36 + 228 · N`          | Per `dark-von` baseline                 |
| `UserBoardingArtifact` (per user)               | `64 + 98 · N`           | slot_index/n + N × (`PubNonce` 66 + `PartialSignature` 32) + 32-B witness |
| All boarding artifacts (per cohort)             | `K · (64 + 98 · N)`     | = `64K + 98KN`                          |
| `Cohort.members`                                | `≈ 72 · K`              | `CohortMember` ≈ 72 B with alignment    |
| Constants (`SlotAttest`, slot/batch roots)      | `≈ 180`                 | Independent of (K, N)                   |
| **Total in-memory footprint**                   | `186K + 98KN + 292N + 180` | Lower bound, ±20 % allocator slack |

### Storage table

Computed from the formula above (rounded; allocator slack means
real RSS is up to 30 % higher).

| K       | N   | RetainedScalars | PublishedSchedule | All artifacts | Members  | Total (formula) | Notes |
|---------|-----|-----------------|-------------------|---------------|----------|------------------|-------|
| 100     | 12  | 768 B           | 2 772 B           | 124.0 KB      | 7.2 KB   | **140 KB**       | Lead row★ |
| 1 000   | 12  | 768 B           | 2 772 B           | 1 213 KB      | 72 KB    | **1.37 MB**      |       |
| 1 000   | 50  | 3 200 B         | 11 436 B          | 4 970 KB      | 72 KB    | **5.10 MB**      |       |
| 10 000  | 12  | 768 B           | 2 772 B           | 11 875 KB     | 720 KB   | **13.62 MB**     |       |

The largest component by far is **all boarding artifacts** (`64K + 98KN`):
at the lead config it's 89 % of total; at K=10000 it's 92 %.

## OOM ceiling

K=10000, N=12 fits comfortably on the 36 GB dev hardware (peak RSS
estimated ≤ 25 MB including allocator overhead). The boarding
super-linearity above K=1000 shows up as wall-clock cost, not
memory pressure; the bench completed without a hint of swap.

A back-of-envelope ceiling: storage stays under 1 GB up to about
**K = 700 000 at N = 12** (formula yields 998 MB). Beyond that, the
operator wants per-cohort sharding rather than tighter packing —
follow-up out of scope for AFT.

## Threshold sentinels

| Configuration   | Wall-clock envelope (Apple M-series) | Notes                           |
|-----------------|-------------------------------------|---------------------------------|
| (K=100,  N=12)  | ≤ 5 s                               | ~6× slack over measured 0.83 s |
| (K=1000, N=12)  | ≤ 60 s                              | ~6.6× slack over measured 9.0 s |
| (K=10000,N=12)  | ≤ 600 s                             | ~3.4× slack over measured 175 s |
| (K=1000, N=50)  | ≤ 120 s                             | ~3.5× slack over measured 34 s  |
