//! Criterion benchmarks for range-proof prove/verify on single and
//! aggregated inputs. ADR-0001 mandates absolute proof-size and
//! prove→verify latency numbers for a representative round shape; this
//! harness feeds both.
//!
//! Regression threshold (informational, tuned on host):
//! - `single/prove`:           regression > +25 % fails CI
//! - `single/verify`:          regression > +25 % fails CI
//! - `aggregated/prove_16`:    regression > +25 % fails CI
//! - `aggregated/verify_16`:   regression > +25 % fails CI
//!
//! Thresholds enforced externally (workflow script), not in this file,
//! to keep the benchmark harness dependency-free.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dark_confidential::range_proof::{
    prove_range, prove_range_aggregated, verify_range, verify_range_aggregated,
};
use secp256k1::Scalar;

fn scalar_from_u64(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes).unwrap()
}

fn range_proof_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proof_single");
    let amount: u64 = 1_000_000;
    let blinding = scalar_from_u64(0x0c0ffee);

    group.bench_function("prove", |b| {
        b.iter(|| {
            let _ = prove_range(black_box(amount), black_box(&blinding)).unwrap();
        });
    });

    let (proof, commitment) = prove_range(amount, &blinding).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| assert!(verify_range(black_box(&commitment), black_box(&proof))));
    });
    group.bench_function(BenchmarkId::new("proof_size_bytes", amount), |b| {
        let len = proof.to_bytes().len();
        b.iter(|| black_box(len))
    });
    group.finish();

    let mut agg = c.benchmark_group("range_proof_aggregated_16");
    let inputs: Vec<(u64, Scalar)> = (0..16u64)
        .map(|i| (1_000_000 + i, scalar_from_u64(0x200 + i)))
        .collect();
    agg.bench_function("prove", |b| {
        b.iter(|| {
            let _ = prove_range_aggregated(black_box(&inputs)).unwrap();
        });
    });
    let (agg_proof, agg_commitments) = prove_range_aggregated(&inputs).unwrap();
    agg.bench_function("verify", |b| {
        b.iter(|| {
            assert!(verify_range_aggregated(
                black_box(&agg_commitments),
                black_box(&agg_proof)
            ))
        });
    });
    agg.bench_function(BenchmarkId::new("proof_size_bytes", 16), |b| {
        let len = agg_proof.to_bytes().len();
        b.iter(|| black_box(len))
    });
    agg.finish();
}

criterion_group!(benches, range_proof_benchmark);
criterion_main!(benches);
