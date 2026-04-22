//! Selective-disclosure compliance proofs over the public commitment path.
//!
//! This module implements an incremental building block for issue #567:
//! proving that one VTXO descends from an ancestor VTXO without revealing any
//! amounts. The current proof format reveals only the public commitment path
//! shared by the two VTXOs plus a Schnorr signature from the VTXO owner.
//!
//! The verifier checks three things:
//! 1. The claimed ancestor commitment path is a prefix of the subject VTXO path.
//! 2. Every revealed commitment is present in the public commitment index.
//! 3. The owner signature binds the exact proof contents.
//!
//! This does **not** yet expose the full nullifier graph, but it is production-
//! ready scaffolding for source-of-funds proofs and is intentionally gated
//! behind the `compliance-proofs` feature.

use std::collections::BTreeSet;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{self, Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use crate::domain::Vtxo;

/// Errors returned when generating or verifying a source-of-funds proof.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SourceProofError {
    /// The ancestor VTXO does not match the subject owner's key.
    #[error("ancestor and subject VTXOs must have the same owner")]
    OwnerMismatch,
    /// The ancestor commitment path is not a prefix of the subject path.
    #[error("ancestor commitment path is not a prefix of the subject path")]
    AncestorNotReachable,
    /// The requested proof depth exceeds the configured maximum.
    #[error("requested proof depth {requested} exceeds max depth {max_depth}")]
    DepthExceeded {
        /// Number of ancestry hops requested or disclosed by the proof.
        requested: usize,
        /// Maximum depth allowed by the caller.
        max_depth: usize,
    },
    /// Proof data is malformed.
    #[error("invalid source proof: {0}")]
    InvalidProof(String),
    /// A commitment in the proof is not known to the verifier.
    #[error("unknown commitment txid in proof: {0}")]
    UnknownCommitment(String),
    /// The owner signature is invalid.
    #[error("invalid owner signature")]
    InvalidSignature,
}

/// A single hop in the disclosed commitment path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceProofHop {
    /// Zero-based hop index from the ancestor toward the subject VTXO.
    pub hop: usize,
    /// Commitment txid before this hop.
    pub from_commitment_txid: String,
    /// Commitment txid after this hop.
    pub to_commitment_txid: String,
}

/// Source-of-funds proof over the public commitment path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceOfFundsProof {
    /// Subject VTXO being proven.
    pub subject_vtxo_id: String,
    /// Ancestor VTXO claimed as the source.
    pub ancestor_vtxo_id: String,
    /// Owner's x-only public key as hex.
    pub owner_pubkey: String,
    /// Maximum disclosure depth the prover agreed to reveal.
    pub max_depth: usize,
    /// Number of entries at the start of `commitment_path` that belong to the ancestor prefix.
    pub ancestor_prefix_len: usize,
    /// Revealed public commitment path from ancestor root to subject root.
    pub commitment_path: Vec<String>,
    /// Per-hop view of the commitment path.
    pub hops: Vec<SourceProofHop>,
    /// Hex-encoded Schnorr signature over the canonical proof message.
    pub owner_signature: String,
}

impl SourceOfFundsProof {
    fn signing_message(&self) -> [u8; 32] {
        let payload = serde_json::json!({
            "ancestor_vtxo_id": self.ancestor_vtxo_id,
            "ancestor_prefix_len": self.ancestor_prefix_len,
            "commitment_path": self.commitment_path,
            "hops": self.hops,
            "max_depth": self.max_depth,
            "owner_pubkey": self.owner_pubkey,
            "subject_vtxo_id": self.subject_vtxo_id,
        });
        sha256::Hash::hash(payload.to_string().as_bytes()).to_byte_array()
    }
}

/// Public commitment index used by verifiers.
#[derive(Debug, Clone, Default)]
pub struct ProofCommitmentIndex {
    commitments: BTreeSet<String>,
}

impl ProofCommitmentIndex {
    /// Build an index from public commitment txids.
    pub fn new<I, S>(commitments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            commitments: commitments.into_iter().map(Into::into).collect(),
        }
    }

    /// Returns true if the given commitment txid is known.
    pub fn contains(&self, commitment_txid: &str) -> bool {
        self.commitments.contains(commitment_txid)
    }
}

/// Build a source-of-funds proof for `subject`, rooted at `ancestor`.
///
/// The ancestor commitment path must be a prefix of the subject commitment
/// path. Only the commitment path is revealed, never the VTXO amounts.
pub fn prove_source_chain(
    subject: &Vtxo,
    ancestor: &Vtxo,
    max_depth: usize,
    owner_secret_key: &SecretKey,
) -> Result<SourceOfFundsProof, SourceProofError> {
    if subject.pubkey != ancestor.pubkey {
        return Err(SourceProofError::OwnerMismatch);
    }

    let ancestor_path = normalized_commitment_path(ancestor);
    let subject_path = normalized_commitment_path(subject);

    if ancestor_path.is_empty() || subject_path.is_empty() {
        return Err(SourceProofError::InvalidProof(
            "both ancestor and subject need at least one public commitment".to_string(),
        ));
    }

    if !subject_path.starts_with(&ancestor_path) {
        return Err(SourceProofError::AncestorNotReachable);
    }

    let disclosed_hops = subject_path.len().saturating_sub(ancestor_path.len());
    if disclosed_hops > max_depth {
        return Err(SourceProofError::DepthExceeded {
            requested: disclosed_hops,
            max_depth,
        });
    }

    let commitment_path = subject_path.clone();
    let hops = commitment_path
        .windows(2)
        .enumerate()
        .map(|(hop, pair)| SourceProofHop {
            hop,
            from_commitment_txid: pair[0].clone(),
            to_commitment_txid: pair[1].clone(),
        })
        .collect::<Vec<_>>();

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, owner_secret_key);
    let owner_pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();

    let unsigned = SourceOfFundsProof {
        subject_vtxo_id: subject.outpoint.to_string(),
        ancestor_vtxo_id: ancestor.outpoint.to_string(),
        owner_pubkey,
        max_depth,
        ancestor_prefix_len: ancestor_path.len(),
        commitment_path,
        hops,
        owner_signature: String::new(),
    };

    let message = secp256k1::Message::from_digest(unsigned.signing_message());
    let signature = secp.sign_schnorr(&message, &keypair);

    Ok(SourceOfFundsProof {
        owner_signature: hex::encode(signature.serialize()),
        ..unsigned
    })
}

/// Verify a source-of-funds proof against the public commitment index.
pub fn verify_source_chain(
    proof: &SourceOfFundsProof,
    public_commitments: &ProofCommitmentIndex,
    max_depth: usize,
) -> Result<(), SourceProofError> {
    if proof.commitment_path.is_empty() {
        return Err(SourceProofError::InvalidProof(
            "commitment path must not be empty".to_string(),
        ));
    }

    if proof.ancestor_prefix_len == 0 || proof.ancestor_prefix_len > proof.commitment_path.len() {
        return Err(SourceProofError::InvalidProof(
            "ancestor prefix length must be within the commitment path".to_string(),
        ));
    }

    let disclosed_hops = proof
        .commitment_path
        .len()
        .saturating_sub(proof.ancestor_prefix_len);
    if disclosed_hops > max_depth || disclosed_hops > proof.max_depth {
        return Err(SourceProofError::DepthExceeded {
            requested: disclosed_hops,
            max_depth: max_depth.min(proof.max_depth),
        });
    }

    let expected_hops = proof
        .commitment_path
        .windows(2)
        .enumerate()
        .map(|(hop, pair)| SourceProofHop {
            hop,
            from_commitment_txid: pair[0].clone(),
            to_commitment_txid: pair[1].clone(),
        })
        .collect::<Vec<_>>();
    if proof.hops != expected_hops {
        return Err(SourceProofError::InvalidProof(
            "hop list does not match commitment path".to_string(),
        ));
    }

    for commitment in &proof.commitment_path {
        if !public_commitments.contains(commitment) {
            return Err(SourceProofError::UnknownCommitment(commitment.clone()));
        }
    }

    let pubkey_bytes = hex::decode(&proof.owner_pubkey)
        .map_err(|e| SourceProofError::InvalidProof(format!("bad owner pubkey hex: {e}")))?;
    let owner_pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| SourceProofError::InvalidProof(format!("bad owner pubkey: {e}")))?;
    let signature_bytes = hex::decode(&proof.owner_signature)
        .map_err(|e| SourceProofError::InvalidProof(format!("bad signature hex: {e}")))?;
    let signature = secp256k1::schnorr::Signature::from_slice(&signature_bytes)
        .map_err(|e| SourceProofError::InvalidProof(format!("bad signature bytes: {e}")))?;

    let secp = Secp256k1::verification_only();
    let message = secp256k1::Message::from_digest(proof.signing_message());
    secp.verify_schnorr(&signature, &message, &owner_pubkey)
        .map_err(|_| SourceProofError::InvalidSignature)
}

fn normalized_commitment_path(vtxo: &Vtxo) -> Vec<String> {
    if !vtxo.commitment_txids.is_empty() {
        return vtxo.commitment_txids.clone();
    }
    if !vtxo.root_commitment_txid.is_empty() {
        return vec![vtxo.root_commitment_txid.clone()];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::VtxoOutpoint;

    fn test_secret_key() -> SecretKey {
        SecretKey::from_slice(&[7u8; 32]).unwrap()
    }

    fn make_vtxo(id: &str, vout: u32, pubkey: &str, commitments: &[&str], amount: u64) -> Vtxo {
        let mut vtxo = Vtxo::new(
            VtxoOutpoint::new(id.to_string(), vout),
            amount,
            pubkey.to_string(),
        );
        vtxo.commitment_txids = commitments.iter().map(|s| s.to_string()).collect();
        vtxo.root_commitment_txid = commitments.first().copied().unwrap_or_default().to_string();
        vtxo
    }

    fn owner_pubkey_hex(secret_key: &SecretKey) -> String {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret_key);
        XOnlyPublicKey::from_keypair(&keypair).0.to_string()
    }

    #[test]
    fn prove_and_verify_three_hop_source_chain() {
        let secret_key = test_secret_key();
        let owner = owner_pubkey_hex(&secret_key);
        let ancestor = make_vtxo("ancestor", 0, &owner, &["c0", "c1"], 5_000);
        let subject = make_vtxo(
            "subject",
            1,
            &owner,
            &["c0", "c1", "c2", "c3", "c4"],
            125_000,
        );

        let proof = prove_source_chain(&subject, &ancestor, 3, &secret_key).unwrap();
        let index = ProofCommitmentIndex::new(["c0", "c1", "c2", "c3", "c4"]);

        verify_source_chain(&proof, &index, 3).unwrap();
        assert_eq!(proof.hops.len(), 4);
        assert_eq!(proof.ancestor_prefix_len, 2);
        assert_eq!(proof.commitment_path, vec!["c0", "c1", "c2", "c3", "c4"]);
        let json = serde_json::to_string(&proof).unwrap();
        assert!(!json.contains("\"amount\""));
    }

    #[test]
    fn doctored_hop_is_rejected() {
        let secret_key = test_secret_key();
        let owner = owner_pubkey_hex(&secret_key);
        let ancestor = make_vtxo("ancestor", 0, &owner, &["c0"], 7_500);
        let subject = make_vtxo("subject", 1, &owner, &["c0", "c1", "c2", "c3"], 42_000);
        let mut proof = prove_source_chain(&subject, &ancestor, 3, &secret_key).unwrap();
        proof.hops[1].to_commitment_txid = "forged".to_string();

        let index = ProofCommitmentIndex::new(["c0", "c1", "c2", "c3", "forged"]);
        let err = verify_source_chain(&proof, &index, 3).unwrap_err();
        assert!(matches!(err, SourceProofError::InvalidProof(_)));
    }

    #[test]
    fn proof_exceeding_depth_is_rejected() {
        let secret_key = test_secret_key();
        let owner = owner_pubkey_hex(&secret_key);
        let ancestor = make_vtxo("ancestor", 0, &owner, &["c0"], 1_000);
        let subject = make_vtxo("subject", 1, &owner, &["c0", "c1", "c2", "c3", "c4"], 2_000);

        let err = prove_source_chain(&subject, &ancestor, 2, &secret_key).unwrap_err();
        assert_eq!(
            err,
            SourceProofError::DepthExceeded {
                requested: 4,
                max_depth: 2,
            }
        );
    }

    #[test]
    fn unknown_commitment_is_rejected() {
        let secret_key = test_secret_key();
        let owner = owner_pubkey_hex(&secret_key);
        let ancestor = make_vtxo("ancestor", 0, &owner, &["c0", "c1"], 11_000);
        let subject = make_vtxo("subject", 1, &owner, &["c0", "c1", "c2"], 12_000);
        let proof = prove_source_chain(&subject, &ancestor, 2, &secret_key).unwrap();
        let index = ProofCommitmentIndex::new(["c0", "c1"]);

        let err = verify_source_chain(&proof, &index, 2).unwrap_err();
        assert_eq!(err, SourceProofError::UnknownCommitment("c2".to_string()));
    }
}
