//! Equivocation evidence for VON-MuSig2.
//!
//! When the operator publishes two valid VON proofs `(R₁, π₁)` and
//! `(R₂, π₂)` with `R₁ ≠ R₂` on the **same** input `x`, the pair is
//! observable proof of misbehaviour: under the honest construction
//! `R = HMAC_SHA256(sk_VON, "DARK-VON-r-v1" || x) · G` is uniquely
//! determined by `(sk_VON, x)`, so two distinct valid `R` values
//! cannot be produced by an honest operator.
//!
//! [`Evidence::from_pair`] takes such a pair, validates that both proofs
//! verify under the operator's `pk_VON`, and builds a self-contained
//! [`Evidence`] blob. [`Evidence::verify`] re-runs the same checks
//! standalone.
//!
//! ## Wire format and size
//!
//! ```text
//!   x         32 B  (the shared input — typically `h_nonce(setup_id, t, b)`)
//!   R₁        33 B
//!   π₁        81 B  (ECVRF proof: Γ || c || s)
//!   R₂        33 B
//!   π₂        81 B
//! ─────────────────
//! Total       260 B
//! ```
//!
//! 260 B exceeds the issue's 200 B target — under our wrapper
//! (ADR-0007 construction (c)) the evidence has to carry both ECVRF
//! proofs in full because each binds a different `alpha' = x || R_i`.
//! On-chain OP_RETURN publication (80 B max) therefore requires a
//! follow-up commit-then-reveal scheme; PSAR's threat model treats
//! off-chain (e.g., gossip / Nostr) publication as sufficient. See
//! ADR-0007 §"Equivocation" for the broader posture.

use dark_von::ecvrf::{Proof, PROOF_LEN};
use dark_von::wrapper;
use secp256k1::PublicKey;
use thiserror::Error;

/// Wire length of [`Evidence::to_bytes`] / [`Evidence::from_bytes`].
pub const EVIDENCE_LEN: usize = 32 + 33 + PROOF_LEN + 33 + PROOF_LEN;

/// Errors raised by [`Evidence::from_pair`] / [`Evidence::verify`] / parsing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EvidenceError {
    #[error("input x must be 32 bytes (h_nonce output)")]
    InputLength,

    #[error("first VON proof does not verify under operator pk")]
    Pair1InvalidProof,

    #[error("second VON proof does not verify under operator pk")]
    Pair2InvalidProof,

    #[error("not equivocating: both pairs use the same R")]
    NotEquivocating,

    #[error("malformed evidence wire bytes")]
    MalformedWire,
}

/// Self-contained equivocation evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub x: [u8; 32],
    pub r1: PublicKey,
    pub proof1: Proof,
    pub r2: PublicKey,
    pub proof2: Proof,
}

impl Evidence {
    /// Build evidence from a candidate pair. Validates both proofs verify
    /// and that `R₁ ≠ R₂`; returns the appropriate error otherwise.
    pub fn from_pair(
        operator_pk_von: &PublicKey,
        x: &[u8],
        pair_a: (&PublicKey, &Proof),
        pair_b: (&PublicKey, &Proof),
    ) -> Result<Self, EvidenceError> {
        if x.len() != 32 {
            return Err(EvidenceError::InputLength);
        }
        wrapper::verify(operator_pk_von, x, pair_a.0, pair_a.1)
            .map_err(|_| EvidenceError::Pair1InvalidProof)?;
        wrapper::verify(operator_pk_von, x, pair_b.0, pair_b.1)
            .map_err(|_| EvidenceError::Pair2InvalidProof)?;
        if pair_a.0 == pair_b.0 {
            return Err(EvidenceError::NotEquivocating);
        }
        let mut x_arr = [0u8; 32];
        x_arr.copy_from_slice(x);
        Ok(Evidence {
            x: x_arr,
            r1: *pair_a.0,
            proof1: pair_a.1.clone(),
            r2: *pair_b.0,
            proof2: pair_b.1.clone(),
        })
    }

    /// Re-validate the evidence against `operator_pk_von`. Anyone with
    /// `pk_VON` can run this check.
    pub fn verify(&self, operator_pk_von: &PublicKey) -> Result<(), EvidenceError> {
        wrapper::verify(operator_pk_von, &self.x, &self.r1, &self.proof1)
            .map_err(|_| EvidenceError::Pair1InvalidProof)?;
        wrapper::verify(operator_pk_von, &self.x, &self.r2, &self.proof2)
            .map_err(|_| EvidenceError::Pair2InvalidProof)?;
        if self.r1 == self.r2 {
            return Err(EvidenceError::NotEquivocating);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; EVIDENCE_LEN] {
        let mut out = [0u8; EVIDENCE_LEN];
        out[..32].copy_from_slice(&self.x);
        out[32..65].copy_from_slice(&self.r1.serialize());
        out[65..146].copy_from_slice(&self.proof1.to_bytes());
        out[146..179].copy_from_slice(&self.r2.serialize());
        out[179..260].copy_from_slice(&self.proof2.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EvidenceError> {
        if bytes.len() != EVIDENCE_LEN {
            return Err(EvidenceError::MalformedWire);
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&bytes[..32]);
        let r1 = PublicKey::from_slice(&bytes[32..65]).map_err(|_| EvidenceError::MalformedWire)?;
        let proof1 =
            Proof::from_slice(&bytes[65..146]).map_err(|_| EvidenceError::MalformedWire)?;
        let r2 =
            PublicKey::from_slice(&bytes[146..179]).map_err(|_| EvidenceError::MalformedWire)?;
        let proof2 =
            Proof::from_slice(&bytes[179..260]).map_err(|_| EvidenceError::MalformedWire)?;
        Ok(Evidence {
            x,
            r1,
            proof1,
            r2,
            proof2,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dark_von::ecvrf;
    use dark_von::wrapper as von_wrapper;
    use secp256k1::{Secp256k1, SecretKey};

    fn fixed_sk() -> SecretKey {
        SecretKey::from_slice(&[0xa1u8; 32]).unwrap()
    }

    /// Construct a "cheat" `(R', π')` for the given `(sk, x)` with a chosen
    /// `r'` ≠ HMAC-derived `r`. Bypasses [`von_wrapper::nonce`]'s deterministic
    /// derivation; serves only to simulate operator misbehaviour for tests.
    fn cheat_pair(
        sk: &SecretKey,
        x: &[u8],
        chosen_r: &SecretKey,
    ) -> (PublicKey, dark_von::ecvrf::Proof) {
        let secp = Secp256k1::new();
        let r_point = PublicKey::from_secret_key(&secp, chosen_r);
        // alpha' = x || R'_compressed
        let mut alpha = Vec::with_capacity(x.len() + 33);
        alpha.extend_from_slice(x);
        alpha.extend_from_slice(&r_point.serialize());
        let (_beta, proof) = ecvrf::prove(sk, &alpha).expect("ecvrf::prove");
        (r_point, proof)
    }

    #[test]
    fn honest_pair_does_not_yield_evidence() {
        let sk = fixed_sk();
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let x = dark_von::hash::h_nonce(&[0xc4u8; 32], 1, 1);

        let n1 = von_wrapper::nonce(&sk, &x).expect("nonce");
        let n2 = von_wrapper::nonce(&sk, &x).expect("nonce");
        // By determinism, R₁ == R₂.
        assert_eq!(n1.r_point, n2.r_point);

        let result =
            Evidence::from_pair(&pk, &x, (&n1.r_point, &n1.proof), (&n2.r_point, &n2.proof));
        assert!(matches!(result, Err(EvidenceError::NotEquivocating)));
    }

    #[test]
    fn dishonest_pair_yields_verifying_evidence() {
        let sk = fixed_sk();
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let x = dark_von::hash::h_nonce(&[0xc4u8; 32], 1, 1);

        // Honest pair.
        let n_honest = von_wrapper::nonce(&sk, &x).expect("nonce");
        // Cheat: use a fresh r' ≠ r_honest.
        let r_cheat_sk = SecretKey::from_slice(&[0x99u8; 32]).unwrap();
        let (r_cheat, proof_cheat) = cheat_pair(&sk, &x, &r_cheat_sk);
        assert_ne!(n_honest.r_point, r_cheat);

        let evidence = Evidence::from_pair(
            &pk,
            &x,
            (&n_honest.r_point, &n_honest.proof),
            (&r_cheat, &proof_cheat),
        )
        .expect("evidence");

        evidence.verify(&pk).expect("evidence verify");

        // Wire round-trip.
        let bytes = evidence.to_bytes();
        assert_eq!(bytes.len(), EVIDENCE_LEN);
        println!("Evidence wire size: {} bytes", bytes.len());
        let parsed = Evidence::from_bytes(&bytes).expect("evidence parse");
        assert_eq!(parsed, evidence);
        parsed.verify(&pk).expect("re-verify");
    }

    #[test]
    fn evidence_rejects_wrong_operator_pk() {
        let sk = fixed_sk();
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let other_pk =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x88u8; 32]).unwrap());
        let x = dark_von::hash::h_nonce(&[0u8; 32], 1, 1);

        let n_honest = von_wrapper::nonce(&sk, &x).unwrap();
        let r_cheat_sk = SecretKey::from_slice(&[0x77u8; 32]).unwrap();
        let (r_cheat, proof_cheat) = cheat_pair(&sk, &x, &r_cheat_sk);
        let evidence = Evidence::from_pair(
            &pk,
            &x,
            (&n_honest.r_point, &n_honest.proof),
            (&r_cheat, &proof_cheat),
        )
        .unwrap();

        assert!(matches!(
            evidence.verify(&other_pk),
            Err(EvidenceError::Pair1InvalidProof)
        ));
    }

    #[test]
    fn input_length_must_be_32() {
        let sk = fixed_sk();
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let n = von_wrapper::nonce(&sk, b"short").unwrap();
        let result = Evidence::from_pair(
            &pk,
            b"short",
            (&n.r_point, &n.proof),
            (&n.r_point, &n.proof),
        );
        assert!(matches!(result, Err(EvidenceError::InputLength)));
    }

    #[test]
    fn malformed_wire_rejected() {
        assert!(matches!(
            Evidence::from_bytes(&[0u8; 100]),
            Err(EvidenceError::MalformedWire)
        ));
    }

    #[test]
    fn evidence_size_under_300_bytes() {
        // Documented size; under 300 B (informational; issue's 200 B target
        // not achievable without algebraic compression, see module doc).
        assert_eq!(EVIDENCE_LEN, 260);
    }
}
