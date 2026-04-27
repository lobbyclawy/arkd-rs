//! Deterministic blinding-factor derivation for Confidential VTXOs (issue #573).
//!
//! Pedersen blinding factors must satisfy two simultaneous goals:
//!
//! - **Reproducible from the seed** so that wallet restore can recover
//!   every commitment opening from `(seed, derivation_index)` alone,
//!   without persisted state.
//! - **Unpredictable to anyone without the seed** so that an observer
//!   cannot link commitments or guess openings.
//!
//! Both fall out of a domain-separated KDF over `(seed, index)` whose
//! output is reduced to a valid secp256k1 scalar.
//!
//! # Transcript
//!
//! ```text
//!     scalar_bytes = SHA-256(
//!         BLINDING_KDF_DST || 0x00 || counter_be || seed || index_be8,
//!     )
//! ```
//!
//! - [`BLINDING_KDF_DST`] is the versioned domain separator. Any change
//!   to this string invalidates every previously-derived blinding, so it
//!   must be a deliberate version bump.
//! - `0x00` is a hard separator following the project convention (see
//!   `nullifier.rs` and `stealth/sender.rs`) so no future DST suffix can
//!   collide with the counter-prefixed encoding.
//! - `counter_be` is a big-endian `u16` starting at `0`. If the digest
//!   reduces to an invalid secp256k1 scalar (zero or above the curve
//!   order `n`) the counter is incremented and the hash retried — the
//!   exact pattern from [`crate::stealth::sender`]. Per-iteration
//!   failure probability is ≈ 2^-128; the loop is capped at
//!   `MAX_KDF_RETRIES` purely to rule out an unbounded loop on misuse.
//! - `index_be8` is the unified VTXO derivation index encoded big-endian.
//!   Callers that prefer to think in `(round_id, vtxo_index_in_round)`
//!   should use [`derive_blinding_with_round`] instead of constructing
//!   the index themselves.
//!
//! # Why hash-and-reduce rather than HMAC-keyed-by-seed
//!
//! HMAC-SHA256 (used in `nullifier.rs`) treats the secret as the key,
//! which is the right shape when the *message* is a public identifier.
//! Here both the seed and the index need to be hashed together, and the
//! retry-counter shape from `stealth/sender.rs` already gives us a
//! well-tested template. Pre-image resistance of SHA-256 still gives us
//! "unpredictable without the seed", and collision resistance gives us
//! "distinct indices produce distinct blindings" with overwhelming
//! probability.
//!
//! # Zeroization
//!
//! The seed enters this module by reference and is fed straight into the
//! hash engine — the engine's internal state is consumed by `finalize`
//! and dropped immediately. The 32-byte digest used as scalar input is
//! returned to the caller wrapped in a [`Scalar`]; downstream code that
//! treats blindings as secrets is responsible for its own zeroization
//! (see `crate::vtxo::ConfidentialVtxo`).

use secp256k1::hashes::{sha256, Hash, HashEngine};
use secp256k1::Scalar;

use crate::{ConfidentialError, Result};

/// Domain separator for blinding-factor derivation. Versioned so a
/// future primitive change can mint v2 without ambiguity.
pub const BLINDING_KDF_DST: &[u8] = b"dark-confidential/blinding/v1";

/// Hard separator byte between the DST and the counter, matching the
/// `nullifier.rs` and `stealth/sender.rs` transcript layouts.
const KDF_SEPARATOR: u8 = 0x00;

/// Maximum number of counter increments before giving up on the KDF.
/// At ≈ 2^-128 per-iteration failure probability, even a handful of
/// retries should never occur in practice; this cap exists purely to
/// rule out an unbounded loop on misuse.
const MAX_KDF_RETRIES: u16 = 256;

/// Length of the wallet seed in bytes.
pub const SEED_LEN: usize = 32;

/// Derive the blinding factor for `vtxo_derivation_index` under `seed`.
///
/// Deterministic in `(seed, vtxo_derivation_index)` and unpredictable to
/// anyone without `seed`. See the module docs for transcript and
/// retry-on-counter details.
///
/// # Errors
///
/// Returns [`ConfidentialError::InvalidInput`] only in the
/// cryptographically-impossible case that `MAX_KDF_RETRIES` consecutive
/// hashes all fall outside the valid secp256k1 scalar range.
pub fn derive_blinding(seed: &[u8; SEED_LEN], vtxo_derivation_index: u64) -> Result<Scalar> {
    for counter in 0..MAX_KDF_RETRIES {
        let digest = kdf_round(seed, vtxo_derivation_index, counter);
        if let Ok(scalar) = Scalar::from_be_bytes(digest) {
            // Reject scalar zero — `Scalar::from_be_bytes` accepts it but
            // it cannot be used as a Pedersen blinding without trivially
            // revealing the committed value.
            if digest != [0u8; 32] {
                return Ok(scalar);
            }
        }
    }
    Err(ConfidentialError::InvalidInput(
        "blinding KDF exhausted retries (cryptographically impossible)",
    ))
}

/// Derive the blinding factor for the `vtxo_index_in_round`-th VTXO of
/// round `round_id`.
///
/// This is the convenience callers should reach for: it constructs the
/// unified `vtxo_derivation_index` from `(round_id, vtxo_index_in_round)`
/// so wallets do not have to track a global counter across rounds. The
/// pack layout is fixed and documented under [`pack_round_index`] so
/// restore-from-seed can re-derive without ambiguity.
pub fn derive_blinding_with_round(
    seed: &[u8; SEED_LEN],
    round_id: u32,
    vtxo_index_in_round: u32,
) -> Result<Scalar> {
    derive_blinding(seed, pack_round_index(round_id, vtxo_index_in_round))
}

/// Combine `(round_id, vtxo_index_in_round)` into the unified u64
/// derivation index used by [`derive_blinding`].
///
/// Layout: `round_id` occupies the high 32 bits, `vtxo_index_in_round`
/// the low 32 bits. The pack is bijective so `(round_id, vtxo_index)`
/// pairs map 1:1 to derivation indices, and re-deriving from a seed only
/// requires remembering the pair.
pub fn pack_round_index(round_id: u32, vtxo_index_in_round: u32) -> u64 {
    (u64::from(round_id) << 32) | u64::from(vtxo_index_in_round)
}

fn kdf_round(seed: &[u8; SEED_LEN], index: u64, counter: u16) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(BLINDING_KDF_DST);
    engine.input(&[KDF_SEPARATOR]);
    engine.input(&counter.to_be_bytes());
    engine.input(seed);
    engine.input(&index.to_be_bytes());
    sha256::Hash::from_engine(engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::HashSet;
    use std::fs;

    #[derive(Debug, Deserialize)]
    struct Vectors {
        version: u8,
        dst: String,
        vectors: Vec<Vector>,
    }

    #[derive(Debug, Deserialize)]
    struct Vector {
        name: String,
        seed_hex: String,
        vtxo_derivation_index: u64,
        blinding_hex: String,
    }

    fn seed_from_hex(hex: &str) -> [u8; SEED_LEN] {
        let bytes = hex::decode(hex).unwrap();
        let mut out = [0u8; SEED_LEN];
        out.copy_from_slice(&bytes);
        out
    }

    fn sample_seed() -> [u8; SEED_LEN] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    #[test]
    fn dst_is_versioned_and_namespaced() {
        // Catch accidental DST drift: any change to this constant
        // invalidates every prior derivation, so it must be a deliberate,
        // version-bumping change.
        assert_eq!(BLINDING_KDF_DST, b"dark-confidential/blinding/v1");
    }

    #[test]
    fn derivation_is_deterministic() {
        let seed = sample_seed();
        let a = derive_blinding(&seed, 42).unwrap();
        let b = derive_blinding(&seed, 42).unwrap();
        assert_eq!(a.to_be_bytes(), b.to_be_bytes());
    }

    #[test]
    fn distinct_seeds_yield_distinct_blindings() {
        let mut other = sample_seed();
        other[0] ^= 0xff;
        let a = derive_blinding(&sample_seed(), 0).unwrap();
        let b = derive_blinding(&other, 0).unwrap();
        assert_ne!(a.to_be_bytes(), b.to_be_bytes());
    }

    #[test]
    fn distinct_indices_yield_distinct_blindings() {
        let seed = sample_seed();
        let a = derive_blinding(&seed, 0).unwrap();
        let b = derive_blinding(&seed, 1).unwrap();
        assert_ne!(a.to_be_bytes(), b.to_be_bytes());
    }

    #[test]
    fn output_is_a_valid_nonzero_scalar() {
        // `Scalar::from_be_bytes` already rejects values >= n; we
        // additionally rule out the zero scalar inside derive_blinding,
        // since a zero blinding trivially reveals the committed value.
        let seed = sample_seed();
        for index in [0u64, 1, 7, 42, 1_000_000, u64::MAX] {
            let scalar = derive_blinding(&seed, index).unwrap();
            assert_ne!(
                scalar.to_be_bytes(),
                [0u8; 32],
                "zero scalar at index {index}"
            );
        }
    }

    #[test]
    fn ten_thousand_indices_produce_distinct_blindings() {
        // AC: 10_000 distinct indices produce distinct blindings.
        const N: u64 = 10_000;
        let seed = sample_seed();
        let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(N as usize);
        for index in 0..N {
            let scalar = derive_blinding(&seed, index).unwrap();
            assert!(
                seen.insert(scalar.to_be_bytes()),
                "blinding collision at index {index}"
            );
        }
    }

    #[test]
    fn pack_round_index_layout() {
        assert_eq!(pack_round_index(0, 0), 0);
        assert_eq!(pack_round_index(0, 1), 1);
        assert_eq!(pack_round_index(1, 0), 1u64 << 32);
        assert_eq!(
            pack_round_index(0xdead_beef, 0xcafe_babe),
            0xdead_beef_cafe_babe,
        );
        assert_eq!(pack_round_index(u32::MAX, u32::MAX), u64::MAX);
    }

    #[test]
    fn pack_round_index_is_bijective_on_components() {
        // Distinct (round_id, vtxo_index) pairs must map to distinct
        // unified indices — otherwise `derive_blinding_with_round` could
        // collide blindings across rounds.
        let pairs = [
            (0u32, 0u32),
            (0, 1),
            (1, 0),
            (1, 1),
            (0xffff_ffff, 0),
            (0, 0xffff_ffff),
        ];
        let mut seen: HashSet<u64> = HashSet::new();
        for (round, index) in pairs {
            assert!(
                seen.insert(pack_round_index(round, index)),
                "pack collision for ({round}, {index})"
            );
        }
    }

    #[test]
    fn derive_with_round_matches_packed_index() {
        let seed = sample_seed();
        let round_id = 7u32;
        let vtxo_index = 13u32;
        let via_round = derive_blinding_with_round(&seed, round_id, vtxo_index).unwrap();
        let via_packed = derive_blinding(&seed, pack_round_index(round_id, vtxo_index)).unwrap();
        assert_eq!(via_round.to_be_bytes(), via_packed.to_be_bytes());
    }

    #[test]
    fn distinct_rounds_yield_distinct_blindings_at_same_vtxo_index() {
        let seed = sample_seed();
        let a = derive_blinding_with_round(&seed, 0, 5).unwrap();
        let b = derive_blinding_with_round(&seed, 1, 5).unwrap();
        assert_ne!(a.to_be_bytes(), b.to_be_bytes());
    }

    #[test]
    fn restore_recomputes_known_blindings_from_seed_alone() {
        // AC: wallet restore reproduces blindings for known VTXOs given
        // only the seed and the (round_id, vtxo_index_in_round) pair.
        let seed = sample_seed();
        let known: Vec<(u32, u32)> = vec![(0, 0), (0, 1), (1, 0), (42, 7), (0xffff, 0xffff)];

        let original: Vec<[u8; 32]> = known
            .iter()
            .map(|(r, i)| {
                derive_blinding_with_round(&seed, *r, *i)
                    .unwrap()
                    .to_be_bytes()
            })
            .collect();

        // Simulate restore: rebuild from the same seed, bytewise compare.
        let restored: Vec<[u8; 32]> = known
            .iter()
            .map(|(r, i)| {
                derive_blinding_with_round(&seed, *r, *i)
                    .unwrap()
                    .to_be_bytes()
            })
            .collect();

        assert_eq!(original, restored);
    }

    #[test]
    fn pinned_vectors_match() {
        let content = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/blinding.json"
        ))
        .unwrap();
        let vectors: Vectors = serde_json::from_str(&content).unwrap();
        assert_eq!(vectors.version, 1);
        assert_eq!(vectors.dst.as_bytes(), BLINDING_KDF_DST);
        assert!(
            vectors.vectors.len() >= 4,
            "need at least 4 pinned vectors, got {}",
            vectors.vectors.len()
        );

        for v in &vectors.vectors {
            let seed = seed_from_hex(&v.seed_hex);
            let got = derive_blinding(&seed, v.vtxo_derivation_index).unwrap();
            assert_eq!(
                hex::encode(got.to_be_bytes()),
                v.blinding_hex,
                "vector {} mismatch",
                v.name
            );
        }
    }
}
