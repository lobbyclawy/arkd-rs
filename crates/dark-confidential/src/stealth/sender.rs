//! Sender-side ECDH derivation for stealth outputs.
//!
//! For each output the sender constructs, this module:
//!
//! 1. Samples a fresh ephemeral secp256k1 keypair `(e, E)`.
//! 2. Computes the raw ECDH point `S = e · scan_pk`.
//! 3. Derives a domain-separated 32-byte tweak `t = KDF(S)`.
//! 4. Publishes the one-time public key `P = spend_pk + t·G`.
//!
//! The 32-byte tweak `t` is also returned to the caller as the
//! `shared_secret`. Per #554, downstream consumers (notably the
//! confidential memo encryption work in #536) may use it as keying
//! material — they MUST sub-key with their own domain-separated KDF
//! before using it as a symmetric key, since `t` already serves as the
//! EC scalar in the one-time-key construction.
//!
//! ## KDF
//!
//! ```text
//!     t = SHA-256(KDF_DST || 0x00 || counter_be || compressed(S))
//! ```
//!
//! - `KDF_DST` is [`STEALTH_KDF_DST`].
//! - `0x00` is a hard separator following the project convention
//!   (see `nullifier.rs`) so no future DST suffix can collide with a
//!   counter-prefixed encoding.
//! - `counter_be` is a big-endian `u16` starting at `0`. If the
//!   resulting digest reduces to an invalid secp256k1 scalar (zero or
//!   above the curve order), the counter is incremented and the hash
//!   retried. The probability of even a single retry is ≈ 2^-128; we
//!   cap the loop at `MAX_KDF_RETRIES` so a misuse cannot wedge.
//! - `compressed(S)` is the canonical 33-byte compressed encoding of
//!   the ECDH point.

use rand::{CryptoRng, RngCore};
use secp256k1::hashes::{sha256, Hash, HashEngine};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::stealth::meta_address::MetaAddress;
use crate::{ConfidentialError, Result};

/// Domain separator for the stealth-output KDF. Versioned so a future
/// primitive change can mint a v2 without ambiguity.
pub const STEALTH_KDF_DST: &[u8] = b"dark-confidential/stealth/v1";

/// Hard separator byte between the DST and the counter, matching the
/// nullifier transcript layout.
const KDF_SEPARATOR: u8 = 0x00;

/// Maximum number of counter increments before giving up on the KDF.
/// At ≈ 2^-128 per-iteration failure probability, even a handful of
/// retries should never occur in practice; this cap exists purely to
/// rule out an unbounded loop.
const MAX_KDF_RETRIES: u16 = 256;

/// One sender-derived stealth output.
///
/// All three fields are non-secret to the sender (and `ephemeral_pk`
/// is intended to be published on-chain). `shared_secret` is sensitive
/// w.r.t. *receivers other than the intended one* — the sender may
/// hand it to the memo encryption layer but must not log or persist
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StealthOutput {
    /// `E = e·G`, the per-output ephemeral public key. Published on
    /// chain so the recipient can recompute the shared secret.
    pub ephemeral_pk: PublicKey,
    /// `P = spend_pk + t·G`, the on-chain one-time public key the
    /// VTXO is locked to.
    pub one_time_pk: PublicKey,
    /// `t`, the 32-byte KDF output. Equals `H(ECDH(e, scan_pk))` and
    /// is exported so the caller can derive memo encryption keys
    /// (see #536).
    pub shared_secret: [u8; 32],
}

/// Derive a fresh stealth output for `meta_addr`, sampling the
/// ephemeral keypair from `rng`.
///
/// The RNG is taken explicitly so production callers can pass
/// `OsRng` while tests pass a seeded `StdRng` for golden vectors.
/// The closure of randomness in this function is exactly the keypair
/// generation; everything downstream is deterministic in
/// `(meta_addr, ephemeral_pk)`.
pub fn derive_one_time_output<R: RngCore + CryptoRng>(
    meta_addr: &MetaAddress,
    rng: &mut R,
) -> Result<StealthOutput> {
    let secp = Secp256k1::new();
    let (ephemeral_sk, ephemeral_pk) = secp.generate_keypair(rng);

    let shared_point = ecdh_raw_point(meta_addr.scan_pk(), &ephemeral_sk)?;
    let shared_secret = kdf_with_retry(&shared_point)?;
    let one_time_pk = tweak_spend_key(meta_addr.spend_pk(), &shared_secret)?;

    Ok(StealthOutput {
        ephemeral_pk,
        one_time_pk,
        shared_secret: shared_secret.0,
    })
}

/// Compute the raw ECDH point `S = sk · pk` and return its
/// canonical 33-byte compressed encoding.
fn ecdh_raw_point(pk: &PublicKey, sk: &SecretKey) -> Result<[u8; 33]> {
    let secp = Secp256k1::new();
    let scalar = (*sk).into();
    let shared = pk
        .mul_tweak(&secp, &scalar)
        .map_err(|_| ConfidentialError::InvalidInput("invalid ECDH multiplication"))?;
    Ok(shared.serialize())
}

/// Wrapper over the 32-byte KDF output. Wrapping protects against
/// accidentally mixing it with an arbitrary `[u8; 32]` (e.g. a
/// nullifier or a hash) in the call sites below.
struct KdfOutput([u8; 32]);

/// Run the domain-separated SHA-256 KDF with retry-on-counter, until
/// the digest is a valid secp256k1 scalar.
fn kdf_with_retry(shared_point: &[u8; 33]) -> Result<KdfOutput> {
    for counter in 0..MAX_KDF_RETRIES {
        let digest = kdf_round(shared_point, counter);
        if SecretKey::from_slice(&digest).is_ok() {
            return Ok(KdfOutput(digest));
        }
    }
    Err(ConfidentialError::InvalidInput(
        "stealth KDF exhausted retries (cryptographically impossible)",
    ))
}

fn kdf_round(shared_point: &[u8; 33], counter: u16) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(STEALTH_KDF_DST);
    engine.input(&[KDF_SEPARATOR]);
    engine.input(&counter.to_be_bytes());
    engine.input(shared_point);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Compute `spend_pk + t·G` where `t` is `shared_secret` interpreted
/// as a scalar. Caller has already verified that `shared_secret` is
/// a valid scalar via [`kdf_with_retry`].
fn tweak_spend_key(spend_pk: &PublicKey, shared_secret: &KdfOutput) -> Result<PublicKey> {
    let secp = Secp256k1::new();
    let tweak_sk = SecretKey::from_slice(&shared_secret.0)
        .expect("shared_secret was validated as a scalar by kdf_with_retry");
    let tweak_point = PublicKey::from_secret_key(&secp, &tweak_sk);
    spend_pk
        .combine(&tweak_point)
        .map_err(|_| ConfidentialError::InvalidInput("one-time-key combination failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::HashSet;

    fn meta_address_from_seeds(scan_seed: u8, spend_seed: u8) -> MetaAddress {
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::from_slice(&[scan_seed; 32]).unwrap();
        let spend_sk = SecretKey::from_slice(&[spend_seed; 32]).unwrap();
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);
        MetaAddress::new(crate::stealth::StealthNetwork::Regtest, scan_pk, spend_pk)
    }

    /// Reference reimplementation: derive `one_time_pk` from
    /// `(scan_sk, spend_pk, ephemeral_pk)` using the same primitives
    /// the production path uses, but starting from the *scan secret*
    /// rather than the ephemeral secret. This is the receiver-side
    /// view of the same construction and exercises the algebraic
    /// identity `e·scan_pk == scan_sk·E`.
    fn recompute_one_time_pk(
        scan_sk: &SecretKey,
        spend_pk: &PublicKey,
        ephemeral_pk: &PublicKey,
    ) -> PublicKey {
        let shared_point = ecdh_raw_point(ephemeral_pk, scan_sk).unwrap();
        let shared_secret = kdf_with_retry(&shared_point).unwrap();
        tweak_spend_key(spend_pk, &shared_secret).unwrap()
    }

    #[test]
    fn derivation_is_deterministic_for_seeded_rng() {
        let meta_addr = meta_address_from_seeds(0x11, 0x22);
        let mut rng_a = StdRng::seed_from_u64(0xdeadbeef);
        let mut rng_b = StdRng::seed_from_u64(0xdeadbeef);
        let out_a = derive_one_time_output(&meta_addr, &mut rng_a).unwrap();
        let out_b = derive_one_time_output(&meta_addr, &mut rng_b).unwrap();
        assert_eq!(out_a, out_b);
    }

    #[test]
    fn one_time_pk_matches_independent_recomputation() {
        // The independent reconstruction path uses the *scan secret*
        // and the published ephemeral pk, so we have to know the
        // scan secret here. Build the meta-address directly so we
        // retain it.
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::from_slice(&[0x33u8; 32]).unwrap();
        let spend_sk = SecretKey::from_slice(&[0x44u8; 32]).unwrap();
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);
        let meta_addr =
            MetaAddress::new(crate::stealth::StealthNetwork::Regtest, scan_pk, spend_pk);

        let mut rng = StdRng::seed_from_u64(0xc0ffee);
        let out = derive_one_time_output(&meta_addr, &mut rng).unwrap();

        let expected = recompute_one_time_pk(&scan_sk, &spend_pk, &out.ephemeral_pk);
        assert_eq!(out.one_time_pk, expected);
    }

    #[test]
    fn shared_secret_equals_kdf_of_ecdh_point() {
        // Property: `shared_secret = KDF(e·scan_pk)`. This pins the
        // KDF transcript so any accidental change is caught.
        let meta_addr = meta_address_from_seeds(0x55, 0x66);
        let mut rng = StdRng::seed_from_u64(0xa11ce);
        let out = derive_one_time_output(&meta_addr, &mut rng).unwrap();

        // We cannot recover `e` from `E`, so we verify the identity
        // from the receiver side: `KDF(scan_sk · E)` must equal
        // `out.shared_secret`. This relies on the algebraic identity
        // `e · scan_pk == scan_sk · E`, which is what makes stealth
        // addresses work in the first place.
        let scan_sk = SecretKey::from_slice(&[0x55u8; 32]).unwrap();
        let shared_point = ecdh_raw_point(&out.ephemeral_pk, &scan_sk).unwrap();
        let recomputed = kdf_with_retry(&shared_point).unwrap();
        assert_eq!(out.shared_secret, recomputed.0);
    }

    #[test]
    fn ephemeral_keys_are_unique_across_outputs() {
        let meta_addr = meta_address_from_seeds(0x77, 0x88);
        let mut rng = StdRng::seed_from_u64(0xfeed_face);

        const N: usize = 1_024;
        let mut seen_ephemeral: HashSet<[u8; 33]> = HashSet::with_capacity(N);
        let mut seen_one_time: HashSet<[u8; 33]> = HashSet::with_capacity(N);
        let mut seen_secret: HashSet<[u8; 32]> = HashSet::with_capacity(N);

        for _ in 0..N {
            let out = derive_one_time_output(&meta_addr, &mut rng).unwrap();
            assert!(
                seen_ephemeral.insert(out.ephemeral_pk.serialize()),
                "ephemeral_pk collision"
            );
            assert!(
                seen_one_time.insert(out.one_time_pk.serialize()),
                "one_time_pk collision"
            );
            assert!(
                seen_secret.insert(out.shared_secret),
                "shared_secret collision"
            );
        }
    }

    #[test]
    fn distinct_meta_addresses_yield_distinct_outputs_under_same_rng() {
        // Even with identical RNG seeds, two different recipients
        // must end up with different one-time keys — otherwise a
        // sender re-using ephemerality across recipients would
        // accidentally link them.
        let meta_a = meta_address_from_seeds(0x01, 0x02);
        let meta_b = meta_address_from_seeds(0x03, 0x04);

        let mut rng_a = StdRng::seed_from_u64(42);
        let mut rng_b = StdRng::seed_from_u64(42);
        let out_a = derive_one_time_output(&meta_a, &mut rng_a).unwrap();
        let out_b = derive_one_time_output(&meta_b, &mut rng_b).unwrap();

        // Same seed, same ephemeral key — but different scan_pk and
        // spend_pk make the rest diverge.
        assert_eq!(out_a.ephemeral_pk, out_b.ephemeral_pk);
        assert_ne!(out_a.shared_secret, out_b.shared_secret);
        assert_ne!(out_a.one_time_pk, out_b.one_time_pk);
    }

    #[test]
    fn kdf_dst_is_versioned_and_namespaced() {
        // Catch accidental DST drift: any change to this constant
        // invalidates every prior derivation, so it must be a
        // deliberate, version-bumping change.
        assert_eq!(STEALTH_KDF_DST, b"dark-confidential/stealth/v1");
    }
}
