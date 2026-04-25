//! Live VTXO store lookup benchmark (issue #535 AC).
//!
//! Acceptance criterion: with 1M VTXOs in the store, `get` and
//! `get_by_nullifier` lookup p99 must be < 100 µs. The bench uses an
//! in-process [`LiveVtxoStore`] with no backend, so the numbers measure
//! the sharded RwLock + HashMap hot path — exactly what production
//! validation calls into.
//!
//! Layout:
//!   - half transparent VTXOs, half confidential, mirroring a realistic
//!     mixed-variant working set.
//!   - the `_hit` benches sample a single pre-inserted target chosen
//!     from somewhere in the middle of the dataset (criterion runs the
//!     same closure thousands of times to compute percentiles, so a
//!     fixed target is fine — the shard distribution comes from the
//!     1M inserts, not the lookup).
//!
//! Override the dataset size with `DARK_VTXO_BENCH_SIZE` (default 1M).
//! The CI gate keeps the 1M default to enforce the AC.

use std::env;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dark_core::domain::vtxo::{
    ConfidentialPayload, Vtxo, VtxoOutpoint, EPHEMERAL_PUBKEY_LEN, NULLIFIER_LEN,
    PEDERSEN_COMMITMENT_LEN,
};
use dark_live_store::vtxo_store::{LiveVtxoStore, Nullifier};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio::runtime::Runtime;

/// Build a transparent VTXO whose outpoint is keyed by `seed` so the
/// shard distribution covers the full 0..255 byte space.
fn make_transparent(seed: u64) -> Vtxo {
    let txid = format!("{seed:064x}");
    Vtxo::new(
        VtxoOutpoint::new(txid, (seed & 0xFFFF) as u32),
        1_000 + (seed % 999),
        format!("pk-{seed}"),
    )
}

/// Build a confidential VTXO with a stable but uniformly-distributed
/// nullifier so the nullifier shard distribution is uniform.
fn make_confidential(seed: u64) -> Vtxo {
    let txid = format!("{seed:064x}");
    let outpoint = VtxoOutpoint::new(txid, (seed & 0xFFFF) as u32);

    let mut hasher: u64 = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut nullifier = [0u8; NULLIFIER_LEN];
    for chunk in nullifier.chunks_mut(8) {
        hasher = hasher.wrapping_add(0xA5A5_A5A5_A5A5_A5A5);
        chunk.copy_from_slice(&hasher.to_le_bytes()[..chunk.len()]);
    }

    let payload = ConfidentialPayload::new(
        [(seed & 0xff) as u8; PEDERSEN_COMMITMENT_LEN],
        Vec::new(),
        nullifier,
        [(seed.wrapping_mul(7) & 0xff) as u8; EPHEMERAL_PUBKEY_LEN],
    );
    Vtxo::new_confidential(outpoint, format!("pk-{seed}"), payload)
}

fn build_store(rt: &Runtime, n: usize) -> (Arc<LiveVtxoStore>, Vec<VtxoOutpoint>, Vec<Nullifier>) {
    let store = Arc::new(LiveVtxoStore::new());
    let mut outpoints = Vec::with_capacity(n);
    let mut nullifiers = Vec::with_capacity(n / 2 + 1);

    rt.block_on(async {
        for i in 0..n {
            let v = if i % 2 == 0 {
                make_transparent(i as u64)
            } else {
                make_confidential(i as u64)
            };
            outpoints.push(v.outpoint.clone());
            if let Some(nul) = v.nullifier().copied() {
                nullifiers.push(nul);
            }
            store.insert(v).await.unwrap();
        }
    });

    (store, outpoints, nullifiers)
}

fn bench_get(c: &mut Criterion) {
    let n: usize = env::var("DARK_VTXO_BENCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);

    let rt = Runtime::new().expect("tokio runtime");
    let (store, outpoints, nullifiers) = build_store(&rt, n);

    let mut group = c.benchmark_group("vtxo_lookup");
    group.throughput(Throughput::Elements(1));

    // 1) get(outpoint) hit — fixed mid-dataset target so the bench is
    //    deterministic across runs. The shard randomness comes from
    //    the 1M dataset inserts, not from the lookup.
    let hit_outpoint = outpoints[outpoints.len() / 2].clone();
    group.bench_with_input(
        BenchmarkId::new("get_hit", n),
        &hit_outpoint,
        |b, target| {
            b.to_async(&rt).iter(|| async {
                let r = store.get(black_box(target)).await.unwrap();
                black_box(r)
            });
        },
    );

    // 2) get(outpoint) miss — fresh outpoint that was never inserted.
    let miss_outpoint = VtxoOutpoint::new("ff".repeat(32), 0xDEAD_BEEF);
    group.bench_with_input(
        BenchmarkId::new("get_miss", n),
        &miss_outpoint,
        |b, target| {
            b.to_async(&rt).iter(|| async {
                let r = store.get(black_box(target)).await.unwrap();
                black_box(r)
            });
        },
    );

    // 3) get_by_nullifier hit — fixed mid-dataset nullifier.
    let hit_null = nullifiers[nullifiers.len() / 2];
    group.bench_with_input(
        BenchmarkId::new("get_by_nullifier_hit", n),
        &hit_null,
        |b, target| {
            b.to_async(&rt).iter(|| async {
                let r = store.get_by_nullifier(black_box(target)).await.unwrap();
                black_box(r)
            });
        },
    );

    // 4) get_by_nullifier miss — fresh random 32 bytes.
    let mut rng = StdRng::seed_from_u64(0x0BAD_CAFE);
    let mut miss_null = [0u8; NULLIFIER_LEN];
    rng.fill(&mut miss_null);
    group.bench_with_input(
        BenchmarkId::new("get_by_nullifier_miss", n),
        &miss_null,
        |b, target| {
            b.to_async(&rt).iter(|| async {
                let r = store.get_by_nullifier(black_box(target)).await.unwrap();
                black_box(r)
            });
        },
    );

    group.finish();
}

criterion_group!(benches, bench_get);
criterion_main!(benches);
