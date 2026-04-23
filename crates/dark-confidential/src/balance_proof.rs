//! Balance proof primitives for Confidential VTXOs.
//!
//! # Identity
//!
//! Given Pedersen commitments `C(v, r) = v·G + r·H` (the convention fixed
//! by [`crate::commitment`]), a confidential transaction balances iff
//!
//! ```text
//!     Σ C_in − Σ C_out − commit(fee, 0) = commit(0, r_excess)
//! ```
//!
//! with `r_excess = Σ r_in − Σ r_out (mod n)`. The amount legs cancel
//! only when `Σ v_in − Σ v_out − fee = 0`, leaving the *excess point*
//!
//! ```text
//!     E  =  r_excess · H
//! ```
//!
//! of which the sender knows the discrete log with respect to `H`. The
//! balance proof is a Schnorr signature over `H` attesting to that
//! knowledge, plus a transcript binding the transaction so the signature
//! is not portable to a different spend.
//!
//! # Construction
//!
//! Per ADR-0001 §"Cross-cutting — constraints on downstream issues":
//!
//! > `#526 (balance proof)` reuses `secp256k1 = 0.29` for the Schnorr
//! > signing of the excess point — not `secp256k1-zkp`'s re-export — to
//! > minimise the surface over which the `-sys` crate's audit assumptions
//! > apply.
//!
//! Because the discrete log is taken with respect to `H` (not the curve
//! base `G`), BIP-340 Schnorr cannot be reused as-is. We roll a standard
//! textbook Schnorr over `H`:
//!
//! ```text
//!     prove: k ← H1(nonce_tag, r_excess, tx_hash)
//!            R = k·H
//!            e = H2(challenge_tag, R, E, tx_hash)  (mod n)
//!            s = k + e·r_excess               (mod n)
//!     verify: check  s·H == R + e·E
//! ```
//!
//! Both `H1` and `H2` are BIP-340-style tagged SHA-256. `H1` uses a
//! distinct tag from `H2` so the nonce derivation cannot collide with the
//! challenge hash.
//!
//! # Transcript bindings
//!
//! The challenge hash mixes `(R, E, tx_hash)`. Binding `E` directly
//! propagates any post-hoc tamper of input/output commitments or the fee
//! — all three enter `E = Σ C_in − Σ C_out − fee·G` on the verifier side
//! — into the challenge, so any tamper flips `e` and the signature fails.
//! `tx_hash` stops the proof from being replayed across different spends
//! that happen to share commitment sets.
//!
//! # Threat model
//!
//! - Blinding-factor reuse across spends is orthogonal to this module;
//!   that risk sits with [`crate::commitment`].
//! - `r_excess = 0` is rejected at prove time. A zero excess collapses
//!   `E` to the curve identity, which would let any `s` verify
//!   (`s·H == R + 0`). Rejection keeps prover-side intent explicit.
//! - Nonce `k` is derived deterministically from `(r_excess, tx_hash)`
//!   via a domain-separated tagged hash. Prover does not need an RNG, so
//!   the signing path is reproducible and not dependent on OS entropy at
//!   prove time. The flip side: if `r_excess` is ever signed against a
//!   *different* `tx_hash` in a future call, the reused `k` remains safe
//!   (messages differ → challenges differ → s values differ → no key
//!   leak). Re-signing the same `(r_excess, tx_hash)` pair produces
//!   identical bytes, which is a feature for audit reproducibility.
//! - Proof bytes (`R || s`) are 65 bytes. `R` is a compressed 33-byte
//!   point; `s` is a canonical 32-byte big-endian scalar in `[0, n)`.
//! - The verifier never reads amounts or blindings — only public
//!   commitments, the fee, the tx hash, and the proof. Secret-data
//!   timing side-channels are confined to the prover.

use secp256k1::{
    hashes::{sha256, Hash, HashEngine},
    PublicKey, Scalar, Secp256k1, SecretKey,
};

use crate::{
    commitment::{pedersen_h, PedersenCommitment},
    ConfidentialError, Result,
};

/// Tag for the Schnorr challenge hash. Domain-separates the balance
/// proof from any other tagged hash used across the dark stack.
pub const CHALLENGE_TAG: &[u8] = b"dark-confidential/balance-proof/v1";

/// Tag for deterministic nonce derivation. Disjoint from
/// [`CHALLENGE_TAG`] so a nonce digest cannot be confused with a
/// challenge digest even if the remaining transcript were identical.
pub const NONCE_TAG: &[u8] = b"dark-confidential/balance-proof/nonce/v1";

/// Balance proof = Schnorr signature over generator `H`.
///
/// Wire encoding is `R (33 bytes) || s (32 bytes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceProof {
    r: [u8; 33],
    s: [u8; 32],
}

impl BalanceProof {
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..33].copy_from_slice(&self.r);
        out[33..].copy_from_slice(&self.s);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 {
            return Err(ConfidentialError::InvalidEncoding(
                "balance proof must be 65 bytes",
            ));
        }
        let mut r = [0u8; 33];
        r.copy_from_slice(&bytes[..33]);
        // Structural check — ensure R parses as a compressed point.
        PublicKey::from_slice(&r)
            .map_err(|_| ConfidentialError::InvalidEncoding("balance proof R is not a point"))?;
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[33..]);
        Ok(Self { r, s })
    }
}

/// Prove knowledge of the excess blinding for a balanced transaction.
///
/// `fee` is mirrored into the challenge only implicitly via the
/// verifier's reconstruction of `E`; the prover never sees `fee·G`
/// directly because the identity holds on blindings alone once amounts
/// cancel. Callers MUST ensure the amounts balance — this function
/// cannot verify that from blindings alone, and a balanced-blindings +
/// unbalanced-amounts pair will produce a proof the verifier rejects.
pub fn prove_balance(
    input_blindings: &[Scalar],
    output_blindings: &[Scalar],
    fee: u64,
    tx_hash: &[u8; 32],
) -> Result<BalanceProof> {
    let _ = fee; // verifier-only; see docstring above.
    let r_excess_sk = excess_scalar(input_blindings, output_blindings)?;
    let secp = Secp256k1::new();
    let h = pedersen_h();

    let r_excess_scalar = scalar_from_secret_key(&r_excess_sk);
    let excess_point = h
        .mul_tweak(&secp, &r_excess_scalar)
        .map_err(|_| ConfidentialError::BalanceProof("excess point at infinity"))?;
    let excess_bytes = excess_point.serialize();

    let k_sk = derive_nonce(&r_excess_sk, tx_hash)?;
    let k_scalar = scalar_from_secret_key(&k_sk);
    let r_point = h
        .mul_tweak(&secp, &k_scalar)
        .map_err(|_| ConfidentialError::BalanceProof("nonce point at infinity"))?;
    let r_bytes = r_point.serialize();

    let e_scalar = challenge_scalar(&r_bytes, &excess_bytes, tx_hash)?;
    let e_r_sk = r_excess_sk
        .mul_tweak(&e_scalar)
        .map_err(|_| ConfidentialError::BalanceProof("challenge·excess product canceled"))?;
    let e_r_scalar = scalar_from_secret_key(&e_r_sk);
    let s_sk = k_sk
        .add_tweak(&e_r_scalar)
        .map_err(|_| ConfidentialError::BalanceProof("signature scalar canceled"))?;

    Ok(BalanceProof {
        r: r_bytes,
        s: s_sk.secret_bytes(),
    })
}

/// Verify a balance proof against the public commitments, fee, and tx hash.
///
/// Returns `true` iff the Schnorr equation holds over the reconstructed
/// excess point. Returns `false` on any parse error, structural mismatch,
/// or signature mismatch.
pub fn verify_balance(
    input_commitments: &[PedersenCommitment],
    output_commitments: &[PedersenCommitment],
    fee: u64,
    tx_hash: &[u8; 32],
    proof: &BalanceProof,
) -> bool {
    verify_balance_inner(input_commitments, output_commitments, fee, tx_hash, proof).is_ok()
}

fn verify_balance_inner(
    input_commitments: &[PedersenCommitment],
    output_commitments: &[PedersenCommitment],
    fee: u64,
    tx_hash: &[u8; 32],
    proof: &BalanceProof,
) -> Result<()> {
    let secp = Secp256k1::new();
    let h = pedersen_h();

    let excess_point = reconstruct_excess_point(input_commitments, output_commitments, fee, &secp)?;
    let excess_bytes = excess_point.serialize();

    let r_point = PublicKey::from_slice(&proof.r)
        .map_err(|_| ConfidentialError::InvalidEncoding("balance proof R is not a point"))?;
    let s_scalar = Scalar::from_be_bytes(proof.s)
        .map_err(|_| ConfidentialError::InvalidEncoding("balance proof s exceeds curve order"))?;

    let e_scalar = challenge_scalar(&proof.r, &excess_bytes, tx_hash)?;

    let lhs = h
        .mul_tweak(&secp, &s_scalar)
        .map_err(|_| ConfidentialError::BalanceProof("s·H rejected"))?;
    let e_e = excess_point
        .mul_tweak(&secp, &e_scalar)
        .map_err(|_| ConfidentialError::BalanceProof("e·E rejected"))?;
    let rhs = r_point
        .combine(&e_e)
        .map_err(|_| ConfidentialError::BalanceProof("R + e·E rejected"))?;

    if lhs == rhs {
        Ok(())
    } else {
        Err(ConfidentialError::BalanceProof("signature did not verify"))
    }
}

/// Rebuild `E = Σ C_in − Σ C_out − fee·G` from public inputs.
///
/// Exposed at module scope so cross-tests can assert the homomorphic
/// identity without reaching into private helpers.
pub fn reconstruct_excess_point(
    input_commitments: &[PedersenCommitment],
    output_commitments: &[PedersenCommitment],
    fee: u64,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<PublicKey> {
    let mut acc: Option<PublicKey> = None;
    for c in input_commitments {
        let pk = PublicKey::from_slice(&c.to_bytes())
            .map_err(|_| ConfidentialError::InvalidEncoding("invalid input commitment"))?;
        acc = Some(match acc {
            None => pk,
            Some(a) => a
                .combine(&pk)
                .map_err(|_| ConfidentialError::BalanceProof("input sum canceled"))?,
        });
    }
    for c in output_commitments {
        let pk = PublicKey::from_slice(&c.to_bytes())
            .map_err(|_| ConfidentialError::InvalidEncoding("invalid output commitment"))?;
        let neg = pk.negate(secp);
        acc = Some(match acc {
            None => neg,
            Some(a) => a
                .combine(&neg)
                .map_err(|_| ConfidentialError::BalanceProof("output sum canceled P"))?,
        });
    }
    if fee > 0 {
        let fee_sk = secret_key_from_u64(fee)?;
        let fee_point = PublicKey::from_secret_key(secp, &fee_sk);
        let neg = fee_point.negate(secp);
        acc = Some(match acc {
            None => neg,
            Some(a) => a
                .combine(&neg)
                .map_err(|_| ConfidentialError::BalanceProof("fee leg canceled P"))?,
        });
    }
    acc.ok_or(ConfidentialError::InvalidInput(
        "balance requires at least one commitment or nonzero fee",
    ))
}

fn excess_scalar(input_blindings: &[Scalar], output_blindings: &[Scalar]) -> Result<SecretKey> {
    let mut acc: Option<SecretKey> = None;
    for b in input_blindings {
        let sk = SecretKey::from_slice(&b.to_be_bytes())
            .map_err(|_| ConfidentialError::InvalidInput("blinding scalar must be non-zero"))?;
        acc = Some(match acc {
            None => sk,
            Some(a) => a
                .add_tweak(b)
                .map_err(|_| ConfidentialError::BalanceProof("input blinding sum canceled"))?,
        });
    }
    for b in output_blindings {
        let sk = SecretKey::from_slice(&b.to_be_bytes())
            .map_err(|_| ConfidentialError::InvalidInput("blinding scalar must be non-zero"))?;
        let neg_sk = sk.negate();
        let neg_scalar = scalar_from_secret_key(&neg_sk);
        acc = Some(match acc {
            None => neg_sk,
            Some(a) => a.add_tweak(&neg_scalar).map_err(|_| {
                ConfidentialError::BalanceProof("output blinding subtraction canceled")
            })?,
        });
    }
    acc.ok_or(ConfidentialError::InvalidInput(
        "balance proof requires at least one blinding on either side",
    ))
}

fn derive_nonce(r_excess: &SecretKey, tx_hash: &[u8; 32]) -> Result<SecretKey> {
    let tag = sha256::Hash::hash(NONCE_TAG).to_byte_array();
    for counter in 0u8..=u8::MAX {
        let mut engine = sha256::Hash::engine();
        engine.input(&tag);
        engine.input(&tag);
        engine.input(&r_excess.secret_bytes());
        engine.input(tx_hash);
        engine.input(&[counter]);
        let digest = sha256::Hash::from_engine(engine).to_byte_array();
        if let Ok(sk) = SecretKey::from_slice(&digest) {
            return Ok(sk);
        }
    }
    Err(ConfidentialError::BalanceProof(
        "nonce derivation exhausted counter",
    ))
}

fn challenge_scalar(
    r_bytes: &[u8; 33],
    excess_bytes: &[u8; 33],
    tx_hash: &[u8; 32],
) -> Result<Scalar> {
    let tag = sha256::Hash::hash(CHALLENGE_TAG).to_byte_array();
    for counter in 0u8..=u8::MAX {
        let mut engine = sha256::Hash::engine();
        engine.input(&tag);
        engine.input(&tag);
        engine.input(r_bytes);
        engine.input(excess_bytes);
        engine.input(tx_hash);
        engine.input(&[counter]);
        let digest = sha256::Hash::from_engine(engine).to_byte_array();
        // Reject 0 and values ≥ n via SecretKey's range check, then
        // convert back to Scalar (always succeeds from [1, n−1]).
        if let Ok(sk) = SecretKey::from_slice(&digest) {
            return Ok(scalar_from_secret_key(&sk));
        }
    }
    Err(ConfidentialError::BalanceProof(
        "challenge derivation exhausted counter",
    ))
}

fn scalar_from_secret_key(sk: &SecretKey) -> Scalar {
    Scalar::from_be_bytes(sk.secret_bytes())
        .expect("SecretKey bytes are always a valid non-zero curve scalar")
}

fn secret_key_from_u64(value: u64) -> Result<SecretKey> {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    SecretKey::from_slice(&bytes)
        .map_err(|_| ConfidentialError::InvalidInput("u64 rejected as curve scalar"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::PedersenCommitment;
    use proptest::prelude::*;
    use serde::Deserialize;
    use std::fs;

    fn scalar(value: u64) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_be_bytes(bytes).unwrap()
    }

    fn commit(amount: u64, blinding: u64) -> PedersenCommitment {
        PedersenCommitment::commit(amount, &scalar(blinding)).unwrap()
    }

    #[derive(Debug, Deserialize)]
    struct DomainVectors {
        challenge_tag: String,
        challenge_tag_hash_hex: String,
        nonce_tag: String,
        nonce_tag_hash_hex: String,
    }

    #[test]
    fn balanced_transaction_verifies() {
        // Amounts: 100+50 in, 120+20 out, fee 10. Balanced.
        // Blindings chosen so r_excess = 111 + 23 − 7 − 27 = 100, non-zero.
        let input_blindings = [scalar(111), scalar(23)];
        let output_blindings = [scalar(7), scalar(27)];
        let fee = 10u64;
        let tx_hash = [0xabu8; 32];

        let inputs = [commit(100, 111), commit(50, 23)];
        let outputs = [commit(120, 7), commit(20, 27)];

        let proof = prove_balance(&input_blindings, &output_blindings, fee, &tx_hash).unwrap();
        assert!(verify_balance(&inputs, &outputs, fee, &tx_hash, &proof));
    }

    #[test]
    fn unbalanced_amounts_do_not_verify() {
        let input_blindings = [scalar(111), scalar(23)];
        let output_blindings = [scalar(7), scalar(27)];
        let tx_hash = [0xabu8; 32];

        // Outputs sum to 140, fee 10 → inputs should total 150. We ship
        // 149 and let the verifier reject.
        let inputs = [commit(99, 111), commit(50, 23)];
        let outputs = [commit(120, 7), commit(20, 27)];
        let fee = 10u64;

        let proof = prove_balance(&input_blindings, &output_blindings, fee, &tx_hash).unwrap();
        assert!(!verify_balance(&inputs, &outputs, fee, &tx_hash, &proof));
    }

    #[test]
    fn tampered_input_blinding_fails_verification() {
        let tx_hash = [0x42u8; 32];
        let input_blindings = [scalar(111), scalar(23)];
        let output_blindings = [scalar(7), scalar(27)];
        let fee = 10u64;

        // Prove under the honest blinding set.
        let proof = prove_balance(&input_blindings, &output_blindings, fee, &tx_hash).unwrap();

        // Build inputs with the FIRST input's blinding perturbed — the
        // verifier reconstructs a different `E`, so the proof fails.
        let inputs = [commit(100, 112), commit(50, 23)]; // 111 → 112
        let outputs = [commit(120, 7), commit(20, 27)];
        assert!(!verify_balance(&inputs, &outputs, fee, &tx_hash, &proof));
    }

    #[test]
    fn tampered_commitment_bytes_fail_verification() {
        let input_blindings = [scalar(111), scalar(23)];
        let output_blindings = [scalar(7), scalar(27)];
        let fee = 10u64;
        let tx_hash = [0x99u8; 32];

        let mut outputs = [commit(120, 7), commit(20, 27)];
        let inputs = [commit(100, 111), commit(50, 23)];
        let proof = prove_balance(&input_blindings, &output_blindings, fee, &tx_hash).unwrap();

        // Post-hoc tamper: swap one output for a malleated variant.
        outputs[1] = commit(21, 27);
        assert!(!verify_balance(&inputs, &outputs, fee, &tx_hash, &proof));
    }

    #[test]
    fn tampered_tx_hash_fails_verification() {
        let input_blindings = [scalar(111)];
        let output_blindings = [scalar(27)];
        let fee = 5u64;
        let tx_hash = [0x11u8; 32];
        let inputs = [commit(50, 111)];
        let outputs = [commit(45, 27)];

        let proof = prove_balance(&input_blindings, &output_blindings, fee, &tx_hash).unwrap();
        let mut other = tx_hash;
        other[0] ^= 0x01;
        assert!(!verify_balance(&inputs, &outputs, fee, &other, &proof));
    }

    #[test]
    fn malleated_proof_bytes_fail_verification() {
        let input_blindings = [scalar(111)];
        let output_blindings = [scalar(27)];
        let fee = 5u64;
        let tx_hash = [0xccu8; 32];
        let inputs = [commit(50, 111)];
        let outputs = [commit(45, 27)];

        let proof = prove_balance(&input_blindings, &output_blindings, fee, &tx_hash).unwrap();

        // Flip a bit in s. Round-trip parses but the signature equation
        // fails.
        let mut bytes = proof.to_bytes();
        bytes[64] ^= 0x01;
        let tampered = BalanceProof::from_bytes(&bytes).unwrap();
        assert!(!verify_balance(&inputs, &outputs, fee, &tx_hash, &tampered));

        // Flip a bit in R. Round-trip *may* fail parse (lands on a
        // non-curve point); if it parses, verification must reject.
        let mut bytes = proof.to_bytes();
        bytes[5] ^= 0x01;
        if let Ok(tampered) = BalanceProof::from_bytes(&bytes) {
            assert!(!verify_balance(&inputs, &outputs, fee, &tx_hash, &tampered));
        }
    }

    #[test]
    fn proof_bytes_round_trip() {
        let input_blindings = [scalar(111), scalar(23)];
        let output_blindings = [scalar(7), scalar(27)];
        let tx_hash = [0x33u8; 32];
        let proof = prove_balance(&input_blindings, &output_blindings, 10, &tx_hash).unwrap();
        let bytes = proof.to_bytes();
        let decoded = BalanceProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(BalanceProof::from_bytes(&[0u8; 64]).is_err());
        assert!(BalanceProof::from_bytes(&[0u8; 66]).is_err());
    }

    #[test]
    fn from_bytes_rejects_non_curve_r() {
        // A 33-byte slice starting with 0x02 and whose x-coord lies off
        // the curve would be rejected. The all-zero prefix-0x02 case is
        // non-curve.
        let mut bytes = [0u8; 65];
        bytes[0] = 0x02;
        assert!(BalanceProof::from_bytes(&bytes).is_err());
    }

    #[test]
    fn zero_excess_is_rejected_at_prove() {
        // Same blinding on input and output → r_excess = 0.
        let input_blindings = [scalar(42)];
        let output_blindings = [scalar(42)];
        let tx_hash = [0u8; 32];
        let err = prove_balance(&input_blindings, &output_blindings, 0, &tx_hash);
        assert!(matches!(err, Err(ConfidentialError::BalanceProof(_))));
    }

    #[test]
    fn empty_blindings_rejected_at_prove() {
        let tx_hash = [0u8; 32];
        let err = prove_balance(&[], &[], 0, &tx_hash);
        assert!(matches!(err, Err(ConfidentialError::InvalidInput(_))));
    }

    #[test]
    fn deterministic_prove_produces_same_bytes() {
        let input_blindings = [scalar(111), scalar(23)];
        let output_blindings = [scalar(7), scalar(27)];
        let tx_hash = [0xaau8; 32];
        let a = prove_balance(&input_blindings, &output_blindings, 10, &tx_hash).unwrap();
        let b = prove_balance(&input_blindings, &output_blindings, 10, &tx_hash).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn homomorphic_identity_matches_commit_module() {
        // Cross-test (AC: "Cross-test with m1-pedersen to confirm the
        // homomorphic identity"):
        //
        //     Σ C_in − Σ C_out − commit(fee, 0) == commit(0, r_excess)
        //
        // commit(fee, 0) cannot be produced via PedersenCommitment::commit
        // because the commit API rejects the zero blinding tweak; we
        // round-trip fee·G through from_bytes. commit(0, r_excess) uses
        // the amount==0 fast path inside the commit module.
        let secp = Secp256k1::new();
        let in_blindings = [scalar(111), scalar(23)];
        let out_blindings = [scalar(7), scalar(27)];
        let fee: u64 = 10;
        let inputs = [commit(100, 111), commit(50, 23)];
        let outputs = [commit(120, 7), commit(20, 27)];

        let r_excess_sk = excess_scalar(&in_blindings, &out_blindings).unwrap();
        let r_excess_scalar = scalar_from_secret_key(&r_excess_sk);
        let expected = PedersenCommitment::commit(0, &r_excess_scalar).unwrap();

        let excess_point = reconstruct_excess_point(&inputs, &outputs, fee, &secp).unwrap();
        let reconstructed = PedersenCommitment::from_bytes(&excess_point.serialize()).unwrap();

        assert_eq!(expected, reconstructed);
    }

    #[test]
    fn domain_separation_vector_matches() {
        let content = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/balance_proof.json"
        ))
        .unwrap();
        let vectors: DomainVectors = serde_json::from_str(&content).unwrap();

        assert_eq!(vectors.challenge_tag.as_bytes(), CHALLENGE_TAG);
        assert_eq!(vectors.nonce_tag.as_bytes(), NONCE_TAG);
        let challenge_hash = sha256::Hash::hash(CHALLENGE_TAG).to_byte_array();
        let nonce_hash = sha256::Hash::hash(NONCE_TAG).to_byte_array();
        assert_eq!(hex::encode(challenge_hash), vectors.challenge_tag_hash_hex);
        assert_eq!(hex::encode(nonce_hash), vectors.nonce_tag_hash_hex);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn random_balanced_transactions_verify(
            // Bound amounts to avoid u64 overflow when summing.
            input_amounts in proptest::collection::vec(1u64..=1_000_000_000, 1..6),
            fee in 0u64..=1_000_000,
            blinding_seeds in proptest::collection::vec(1u64..u64::MAX / 2, 2..12),
            // Output split seed — deterministic partition of totals
            split_seed in any::<u64>(),
        ) {
            // Ensure enough blindings: we need |inputs| + |outputs|.
            // Outputs are derived as a deterministic 2-way split of the
            // excess-over-fee.
            prop_assume!(blinding_seeds.len() >= input_amounts.len() + 2);

            let total_in: u128 = input_amounts.iter().map(|x| *x as u128).sum();
            let fee128 = fee as u128;
            prop_assume!(total_in > fee128);

            let payable = total_in - fee128;
            // Split `payable` into two outputs via split_seed mod payable.
            let first = (split_seed as u128) % payable;
            let second = payable - first;
            prop_assume!(first > 0 && second > 0);

            let output_amounts = [first as u64, second as u64];

            let input_blindings: Vec<Scalar> = blinding_seeds[..input_amounts.len()]
                .iter()
                .map(|s| scalar(*s))
                .collect();
            let output_blindings: Vec<Scalar> = blinding_seeds
                [input_amounts.len()..input_amounts.len() + 2]
                .iter()
                .map(|s| scalar(*s))
                .collect();

            // Rule out r_excess = 0 — infinitesimally unlikely with
            // distinct seeds but rejected if it happens.
            let sum_in = input_blindings
                .iter()
                .fold(0u128, |acc, s| acc.wrapping_add(scalar_low128(s)));
            let sum_out = output_blindings
                .iter()
                .fold(0u128, |acc, s| acc.wrapping_add(scalar_low128(s)));
            prop_assume!(sum_in != sum_out);

            let inputs: Vec<PedersenCommitment> = input_amounts
                .iter()
                .zip(input_blindings.iter())
                .map(|(v, r)| PedersenCommitment::commit(*v, r).unwrap())
                .collect();
            let outputs: Vec<PedersenCommitment> = output_amounts
                .iter()
                .zip(output_blindings.iter())
                .map(|(v, r)| PedersenCommitment::commit(*v, r).unwrap())
                .collect();

            let tx_hash = [0x77u8; 32];
            let proof = prove_balance(&input_blindings, &output_blindings, fee, &tx_hash)
                .unwrap();
            prop_assert!(verify_balance(&inputs, &outputs, fee, &tx_hash, &proof));

            // Tamper: bump any one input amount by 1 → unbalanced → reject.
            let mut tampered = inputs.clone();
            tampered[0] = PedersenCommitment::commit(
                input_amounts[0].wrapping_add(1),
                &input_blindings[0],
            )
            .unwrap();
            prop_assert!(!verify_balance(&tampered, &outputs, fee, &tx_hash, &proof));
        }
    }

    fn scalar_low128(s: &Scalar) -> u128 {
        let b = s.to_be_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&b[16..]);
        u128::from_be_bytes(out)
    }
}
