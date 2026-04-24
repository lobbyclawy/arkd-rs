//! Nullifier derivation for Confidential VTXOs.
//!
//! Implements the scheme fixed by ADR-0002
//! (`docs/adr/0002-nullifier-derivation.md`):
//!
//! ```text
//!     nullifier = HMAC-SHA256(
//!         key = secret_key_bytes,
//!         msg = b"dark-confidential/nullifier" || 0x00 || version || vtxo_id_bytes,
//!     )
//! ```
//!
//! - `secret_key_bytes` — 32 bytes, the confidential spend secret.
//! - The `0x00` byte is a hard separator so no future DST suffix can
//!   collide with a version-prefixed encoding.
//! - `version` is the byte [`NULLIFIER_VERSION_V1`]. Versioning lives
//!   *inside* the HMAC input, not on the wire output, so migrating to a
//!   new primitive does not widen stored nullifier columns.
//! - `vtxo_id_bytes` is the canonical 36-byte encoding
//!   `32-byte txid || 4-byte big-endian vout` defined by the ADR.
//!   Callers MUST NOT invent ad-hoc encodings; use [`VtxoId`] or
//!   [`encode_vtxo_id`].
//!
//! # Note on the issue text
//!
//! Issue #527's task description types `vtxo_id` as `&[u8; 32]`. That
//! pre-dates ADR-0002, which canonicalises the identifier at 36 bytes
//! (txid + vout). The ADR is the controlling document — mismatched
//! lengths would silently change which nullifier maps to which VTXO, so
//! we take `&[u8; 36]` here and offer [`VtxoId`] as the ergonomic
//! constructor. Downstream issues (#530, #538, #539) are all scoped to
//! opaque 32-byte nullifier outputs and do not care about the input
//! length.
//!
//! # Zeroization
//!
//! The spend secret enters this module only via `&SecretKey`. We extract
//! its byte view into a [`zeroize::Zeroizing`] buffer that wipes on
//! drop, feed it into HMAC, and release the MAC engine immediately.
//! `secp256k1::SecretKey` itself is `Copy` + `Drop`-zeroizing upstream
//! — that choice is upstream's to defend; we do not introduce any new
//! `Copy` type that carries secret bytes in this path. [`VtxoId`] is
//! `Copy` on purpose: it holds public identifier bytes only.
//!
//! The output 32-byte nullifier is **public**. We do not zeroize it.

use hmac::{Hmac, Mac};
use secp256k1::SecretKey;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Domain separator, exactly as specified in ADR-0002.
pub const NULLIFIER_DST: &[u8] = b"dark-confidential/nullifier";

/// Hard separator byte between DST and version.
pub const NULLIFIER_SEPARATOR: u8 = 0x00;

/// Current nullifier derivation version.
///
/// ADR-0002: "any future primitive change must mint a new version byte,
/// not reinterpret v1".
pub const NULLIFIER_VERSION_V1: u8 = 0x01;

/// Length of the canonical VTXO identifier bytes, per ADR-0002:
/// `32-byte txid || 4-byte big-endian vout`.
pub const VTXO_ID_LEN: usize = 36;

/// Length of a nullifier in bytes. HMAC-SHA256 output width.
pub const NULLIFIER_LEN: usize = 32;

/// Returns the current nullifier version byte so on-wire formats can
/// evolve without reading the constant directly.
pub const fn nullifier_version() -> u8 {
    NULLIFIER_VERSION_V1
}

type HmacSha256 = Hmac<Sha256>;

/// Derive the 32-byte nullifier for `vtxo_id` under `secret_key`.
///
/// Deterministic, collision-resistant, and one-way w.r.t. the secret
/// key. See the module docs for transcript and zeroization specifics.
pub fn compute_nullifier(
    secret_key: &SecretKey,
    vtxo_id: &[u8; VTXO_ID_LEN],
) -> [u8; NULLIFIER_LEN] {
    let sk_bytes = Zeroizing::new(secret_key.secret_bytes());
    let mut mac = HmacSha256::new_from_slice(sk_bytes.as_ref())
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(NULLIFIER_DST);
    mac.update(&[NULLIFIER_SEPARATOR]);
    mac.update(&[NULLIFIER_VERSION_V1]);
    mac.update(vtxo_id);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; NULLIFIER_LEN];
    out.copy_from_slice(&tag);
    out
}

/// Canonical VTXO identifier for nullifier derivation.
///
/// The ADR pins the on-the-wire encoding as `txid || vout_be`; this
/// struct is the one-and-only sanctioned constructor so nothing
/// downstream re-invents the layout. Hold it by value where convenient
/// — it carries no secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VtxoId {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl VtxoId {
    pub const fn new(txid: [u8; 32], vout: u32) -> Self {
        Self { txid, vout }
    }

    pub fn to_bytes(&self) -> [u8; VTXO_ID_LEN] {
        encode_vtxo_id(&self.txid, self.vout)
    }
}

/// Encode `(txid, vout)` into the ADR-0002 canonical 36-byte layout.
pub fn encode_vtxo_id(txid: &[u8; 32], vout: u32) -> [u8; VTXO_ID_LEN] {
    let mut out = [0u8; VTXO_ID_LEN];
    out[..32].copy_from_slice(txid);
    out[32..].copy_from_slice(&vout.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde::Deserialize;
    use std::collections::HashSet;
    use std::fs;

    fn sk_from_hex(hex: &str) -> SecretKey {
        let bytes = hex::decode(hex).unwrap();
        SecretKey::from_slice(&bytes).unwrap()
    }

    fn id_from_hex(hex: &str) -> [u8; VTXO_ID_LEN] {
        let bytes = hex::decode(hex).unwrap();
        let mut out = [0u8; VTXO_ID_LEN];
        out.copy_from_slice(&bytes);
        out
    }

    #[derive(Debug, Deserialize)]
    struct Vectors {
        version: u8,
        dst: String,
        vectors: Vec<Vector>,
    }

    #[derive(Debug, Deserialize)]
    struct Vector {
        name: String,
        secret_key_hex: String,
        vtxo_id_hex: String,
        nullifier_hex: String,
    }

    #[test]
    fn version_is_one() {
        assert_eq!(nullifier_version(), 0x01);
    }

    #[test]
    fn encode_vtxo_id_layout() {
        let txid = [0xaau8; 32];
        let vout = 0x1234_5678u32;
        let bytes = encode_vtxo_id(&txid, vout);
        assert_eq!(&bytes[..32], &txid);
        assert_eq!(&bytes[32..], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn vtxo_id_to_bytes_matches_encoder() {
        let txid = [0x11u8; 32];
        let id = VtxoId::new(txid, 7);
        assert_eq!(id.to_bytes(), encode_vtxo_id(&txid, 7));
    }

    #[test]
    fn adr_0002_vector_c_secret_key_is_invalid() {
        // Document the ADR-0002 bug: Vector C's secret_key_hex
        // `ffffffffffffffffffffffffffffffff00000000000000000000000000000001`
        // is above the secp256k1 group order n, so SecretKey::from_slice
        // rejects it. This test exists so the discrepancy stays visible
        // in CI and is not silently worked around. ADR-0002 needs an
        // amendment substituting a valid scalar (e.g. n−1 for the same
        // "near upper bound" stress intent).
        let bytes = hex::decode("ffffffffffffffffffffffffffffffff00000000000000000000000000000001")
            .unwrap();
        assert!(SecretKey::from_slice(&bytes).is_err());
    }

    #[test]
    fn adr_0002_known_answer_vectors_match() {
        let content = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/nullifier.json"
        ))
        .unwrap();
        let vectors: Vectors = serde_json::from_str(&content).unwrap();
        assert_eq!(vectors.version, NULLIFIER_VERSION_V1);
        assert_eq!(vectors.dst.as_bytes(), NULLIFIER_DST);
        for v in &vectors.vectors {
            let sk = sk_from_hex(&v.secret_key_hex);
            let id = id_from_hex(&v.vtxo_id_hex);
            let got = compute_nullifier(&sk, &id);
            assert_eq!(
                hex::encode(got),
                v.nullifier_hex,
                "ADR-0002 vector {} mismatch",
                v.name
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn determinism(
            sk_bytes in proptest::array::uniform32(any::<u8>()),
            txid in proptest::array::uniform32(any::<u8>()),
            vout in any::<u32>(),
        ) {
            prop_assume!(sk_bytes != [0u8; 32]);
            let Ok(sk) = SecretKey::from_slice(&sk_bytes) else { return Ok(()); };
            let id = encode_vtxo_id(&txid, vout);
            let a = compute_nullifier(&sk, &id);
            let b = compute_nullifier(&sk, &id);
            prop_assert_eq!(a, b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        #[test]
        fn distinct_inputs_produce_distinct_outputs(
            sk_bytes_a in proptest::array::uniform32(any::<u8>()),
            sk_bytes_b in proptest::array::uniform32(any::<u8>()),
            id_a in proptest::array::uniform32(any::<u8>()),
            id_b in proptest::array::uniform32(any::<u8>()),
            vout_a in any::<u32>(),
            vout_b in any::<u32>(),
        ) {
            prop_assume!(sk_bytes_a != sk_bytes_b || id_a != id_b || vout_a != vout_b);
            prop_assume!(sk_bytes_a != [0u8; 32] && sk_bytes_b != [0u8; 32]);
            let Ok(sk_a) = SecretKey::from_slice(&sk_bytes_a) else { return Ok(()); };
            let Ok(sk_b) = SecretKey::from_slice(&sk_bytes_b) else { return Ok(()); };
            let id_a_full = encode_vtxo_id(&id_a, vout_a);
            let id_b_full = encode_vtxo_id(&id_b, vout_b);
            let n_a = compute_nullifier(&sk_a, &id_a_full);
            let n_b = compute_nullifier(&sk_b, &id_b_full);
            prop_assert_ne!(n_a, n_b);
        }
    }

    /// Collision-resistance smoke test: 1M random inputs, zero observed
    /// collisions (AC: "1M random inputs, no collisions").
    ///
    /// Gated behind `--ignored` because 1M HMAC-SHA256 operations in
    /// debug mode is ~40s on a laptop; release brings it under 5s. Run
    /// via `cargo test -p dark-confidential --release collision_resistance -- --ignored --nocapture`.
    #[test]
    #[ignore = "1M HMAC iterations — run with --release and --ignored"]
    fn collision_resistance_one_million() {
        use rand::{rngs::SmallRng, Rng, SeedableRng};
        const N: usize = 1_000_000;
        let mut rng = SmallRng::seed_from_u64(0xc0ffee_u64);
        let mut seen: HashSet<[u8; NULLIFIER_LEN]> = HashSet::with_capacity(N);
        let mut sk_buf = [0u8; 32];
        let mut id_buf = [0u8; VTXO_ID_LEN];
        for _ in 0..N {
            let sk = loop {
                rng.fill(&mut sk_buf[..]);
                if let Ok(sk) = SecretKey::from_slice(&sk_buf) {
                    break sk;
                }
            };
            rng.fill(&mut id_buf[..]);
            let n = compute_nullifier(&sk, &id_buf);
            assert!(seen.insert(n), "unexpected nullifier collision");
        }
    }
}
