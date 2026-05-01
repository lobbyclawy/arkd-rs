//! VON-MuSig2 setup phase.
//!
//! `Setup::run(operator_sk, setup_id, n)` wraps
//! [`dark_von::schedule::generate`] (#657) and returns:
//!
//! - [`PublishedSchedule`]: the operator's setup-time broadcast `Λ`,
//!   serializable to a canonical CBOR wire format via
//!   [`PublishedSchedule::to_cbor`] / [`PublishedSchedule::from_cbor`].
//! - [`RetainedScalars`]: the operator-retained scalars `{r_{t,b}}`
//!   that feed the per-epoch signing flow (#663). **Never serializable**:
//!   the underlying `secp256k1::SecretKey` auto-zeroizes on drop, so
//!   the scalars wipe when the wrapper goes out of scope.
//!
//! Wire-format choice (CBOR via `ciborium`) per ADR-0008's preference
//! for inspectability over byte tightness: future on-the-wire schedule
//! audit tooling can use any CBOR diagnostic decoder, no project-specific
//! parser needed.

use dark_von::ecvrf::Proof;
use dark_von::schedule::{self, PublicEntry, PublicSchedule, SecretSchedule, MAX_HORIZON};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

use crate::error::VonMusig2Error;

/// Setup-time published schedule `Λ` per ADR-0007.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishedSchedule {
    #[serde(with = "serde_bytes")]
    pub setup_id: Vec<u8>,
    pub n: u32,
    pub entries: Vec<PublishedEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishedEntry {
    /// 33-byte compressed point for `b = 1`.
    #[serde(with = "serde_bytes")]
    pub r1: Vec<u8>,
    /// 81-byte VON proof for `b = 1`.
    #[serde(with = "serde_bytes")]
    pub proof1: Vec<u8>,
    /// 33-byte compressed point for `b = 2`.
    #[serde(with = "serde_bytes")]
    pub r2: Vec<u8>,
    /// 81-byte VON proof for `b = 2`.
    #[serde(with = "serde_bytes")]
    pub proof2: Vec<u8>,
}

impl PublishedSchedule {
    /// Build from a `dark_von` `PublicSchedule`.
    pub fn from_dark_von(s: &PublicSchedule) -> Self {
        let entries = s
            .entries
            .iter()
            .map(|(e1, e2)| PublishedEntry {
                r1: e1.r_point.serialize().to_vec(),
                proof1: e1.proof.to_bytes().to_vec(),
                r2: e2.r_point.serialize().to_vec(),
                proof2: e2.proof.to_bytes().to_vec(),
            })
            .collect();
        Self {
            setup_id: s.setup_id.to_vec(),
            n: s.n,
            entries,
        }
    }

    /// Reconstruct a `dark_von` `PublicSchedule` (validates every embedded byte).
    pub fn to_dark_von(&self) -> Result<PublicSchedule, VonMusig2Error> {
        if self.setup_id.len() != 32 {
            return Err(VonMusig2Error::MalformedPublishedSchedule(
                "setup_id must be 32 bytes",
            ));
        }
        if self.n == 0 {
            return Err(VonMusig2Error::MalformedPublishedSchedule("n must be ≥ 1"));
        }
        if self.n > MAX_HORIZON {
            return Err(VonMusig2Error::MalformedPublishedSchedule(
                "n exceeds MAX_HORIZON",
            ));
        }
        if self.entries.len() != self.n as usize {
            return Err(VonMusig2Error::MalformedPublishedSchedule(
                "entries length disagrees with n",
            ));
        }
        let mut setup_id = [0u8; 32];
        setup_id.copy_from_slice(&self.setup_id);
        let mut entries = Vec::with_capacity(self.n as usize);
        for e in &self.entries {
            let r1 = parse_point(&e.r1)?;
            let proof1 = parse_proof(&e.proof1)?;
            let r2 = parse_point(&e.r2)?;
            let proof2 = parse_proof(&e.proof2)?;
            entries.push((
                PublicEntry {
                    r_point: r1,
                    proof: proof1,
                },
                PublicEntry {
                    r_point: r2,
                    proof: proof2,
                },
            ));
        }
        Ok(PublicSchedule {
            setup_id,
            n: self.n,
            entries,
        })
    }

    /// Serialise to canonical CBOR.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)
            .expect("ciborium serialise to Vec is infallible");
        buf
    }

    /// Parse from canonical CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, VonMusig2Error> {
        ciborium::de::from_reader(bytes).map_err(|e| VonMusig2Error::Cbor(e.to_string()))
    }
}

fn parse_point(bytes: &[u8]) -> Result<PublicKey, VonMusig2Error> {
    if bytes.len() != 33 {
        return Err(VonMusig2Error::MalformedPublishedSchedule(
            "R must be 33 bytes",
        ));
    }
    PublicKey::from_slice(bytes)
        .map_err(|_| VonMusig2Error::MalformedPublishedSchedule("invalid R point"))
}

fn parse_proof(bytes: &[u8]) -> Result<Proof, VonMusig2Error> {
    Proof::from_slice(bytes)
        .map_err(|_| VonMusig2Error::MalformedPublishedSchedule("invalid proof bytes"))
}

/// Operator-retained scalars `{r_{t,b}}`. Wraps [`SecretSchedule`]; the
/// inner `SecretKey` instances auto-zeroize on drop (`secp256k1 = 0.29`'s
/// `Drop` impl), so the wrapper has zeroizing storage by construction.
///
/// **Never serializable** through the default API surface.
pub struct RetainedScalars {
    pub(crate) inner: SecretSchedule,
}

impl RetainedScalars {
    pub fn setup_id(&self) -> &[u8; 32] {
        &self.inner.setup_id
    }

    pub fn n(&self) -> u32 {
        self.inner.n
    }

    /// Look up `r_{t, b}` for `t ∈ [1, n]` and `b ∈ {1, 2}`.
    pub fn r(&self, t: u32, b: u8) -> Option<&SecretKey> {
        self.inner.r(t, b)
    }
}

/// Setup-phase entry point.
pub struct Setup;

impl Setup {
    /// Generate `(Λ, retained)` for a horizon of `n` slots.
    pub fn run(
        operator_sk: &SecretKey,
        setup_id: &[u8; 32],
        n: u32,
    ) -> Result<(PublishedSchedule, RetainedScalars), VonMusig2Error> {
        let (public, secret) = schedule::generate(operator_sk, setup_id, n)?;
        Ok((
            PublishedSchedule::from_dark_von(&public),
            RetainedScalars { inner: secret },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dark_von::wrapper;
    use secp256k1::Secp256k1;

    fn fixed_sk() -> SecretKey {
        SecretKey::from_slice(&[0xa7u8; 32]).unwrap()
    }

    #[test]
    fn run_horizons_round_trip_serde_and_verify_each_entry() {
        let secp = Secp256k1::new();
        let sk = fixed_sk();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let setup_id = [0xc4u8; 32];

        for n in [1u32, 4, 12] {
            let (published, retained) = Setup::run(&sk, &setup_id, n).expect("setup");
            assert_eq!(retained.n(), n);
            assert_eq!(*retained.setup_id(), setup_id);
            assert_eq!(published.n, n);
            assert_eq!(published.entries.len(), n as usize);
            assert_eq!(published.setup_id, setup_id.to_vec());

            let cbor = published.to_cbor();
            if n == 12 {
                println!("PublishedSchedule CBOR size at N=12: {} bytes", cbor.len());
            }
            let round_tripped = PublishedSchedule::from_cbor(&cbor).expect("cbor parse");
            assert_eq!(round_tripped.n, n);
            assert_eq!(round_tripped.entries.len(), n as usize);

            let public = round_tripped.to_dark_von().expect("dark-von reconstruct");
            for t in 1..=n {
                for b in [1u8, 2u8] {
                    let entry = public.entry(t, b).expect("entry");
                    let x = dark_von::hash::h_nonce(&setup_id, t, b);
                    wrapper::verify(&pk, &x, &entry.r_point, &entry.proof)
                        .unwrap_or_else(|_| panic!("verify failed at (t={t}, b={b})"));
                }
            }
        }
    }

    #[test]
    fn cbor_round_trip_preserves_bytes() {
        let sk = fixed_sk();
        let setup_id = [0xd8u8; 32];
        let (published, _retained) = Setup::run(&sk, &setup_id, 4).unwrap();

        let cbor1 = published.to_cbor();
        let round = PublishedSchedule::from_cbor(&cbor1).unwrap();
        let cbor2 = round.to_cbor();
        assert_eq!(cbor1, cbor2, "CBOR encoding not stable across round-trip");
    }

    #[test]
    fn malformed_setup_id_rejected() {
        let bad = PublishedSchedule {
            setup_id: vec![0u8; 31],
            n: 1,
            entries: vec![PublishedEntry {
                r1: vec![0u8; 33],
                proof1: vec![0u8; 81],
                r2: vec![0u8; 33],
                proof2: vec![0u8; 81],
            }],
        };
        assert!(matches!(
            bad.to_dark_von(),
            Err(VonMusig2Error::MalformedPublishedSchedule(_))
        ));
    }

    #[test]
    fn malformed_n_zero_rejected() {
        let bad = PublishedSchedule {
            setup_id: vec![0u8; 32],
            n: 0,
            entries: vec![],
        };
        assert!(matches!(
            bad.to_dark_von(),
            Err(VonMusig2Error::MalformedPublishedSchedule(_))
        ));
    }

    #[test]
    fn entries_length_mismatch_rejected() {
        let bad = PublishedSchedule {
            setup_id: vec![0u8; 32],
            n: 4,
            entries: vec![],
        };
        assert!(matches!(
            bad.to_dark_von(),
            Err(VonMusig2Error::MalformedPublishedSchedule(_))
        ));
    }

    #[test]
    fn invalid_r_point_rejected() {
        let sk = fixed_sk();
        let setup_id = [0u8; 32];
        let (mut published, _) = Setup::run(&sk, &setup_id, 1).unwrap();
        published.entries[0].r1 = vec![0u8; 33]; // not on curve
        assert!(matches!(
            published.to_dark_von(),
            Err(VonMusig2Error::MalformedPublishedSchedule(_))
        ));
    }

    #[test]
    fn retained_scalars_lookup() {
        let sk = fixed_sk();
        let (_, retained) = Setup::run(&sk, &[0u8; 32], 4).unwrap();
        assert!(retained.r(1, 1).is_some());
        assert!(retained.r(4, 2).is_some());
        assert!(retained.r(0, 1).is_none());
        assert!(retained.r(5, 1).is_none());
        assert!(retained.r(1, 3).is_none());
    }
}
