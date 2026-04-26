//! Source-of-funds proofs over the linkable graph (#567).
//!
//! A wallet uses this proof to convince an auditor that a target VTXO traces
//! back, hop-by-hop, to a stated source set of on-chain UTXOs or Ark round
//! commitments. The proof reveals the *graph shape* — outpoints and signed
//! transitions — but never the amounts at intermediate hops.
//!
//! # Proof shape
//!
//! - [`SourceOfFundsProof`] is an ordered list of [`HopProof`]s. The first
//!   hop's input outpoint must equal one of the [`SourceLink`]s in
//!   `source_set`, and the last hop's output outpoint must equal the target
//!   `vtxo_outpoint`. Each interior boundary chains: `hop[i].next_outpoint
//!   == hop[i+1].prev_outpoint` and the corresponding commitments must be
//!   identical bytes (same opening on both sides of the seam).
//!
//! - Each [`HopProof`] is sealed by a BIP-340 Schnorr signature from the
//!   hop's owner over a tagged hash of its (`hop_index`, `prev_outpoint`,
//!   `next_outpoint`, `input_commitment`, `output_commitment`,
//!   `signer_pubkey`, `transcript_hash`). The `hop_index` and
//!   `transcript_hash` together bind the signature to a specific position
//!   in a specific chain — a hop signed at index `k` of chain `T` cannot
//!   be replayed at index `k'` or in chain `T' != T`.
//!
//! - [`SourceOfFundsProof::transcript_hash`] commits to the ordered tuple
//!   `(DST, source_set, vtxo_outpoint, hops_count, all hop digests)`. It is
//!   recomputed by the verifier and compared byte-for-byte; it is included
//!   in each per-hop signature so a hop signed for one chain cannot be
//!   reordered or grafted into another.
//!
//! # What is and is not revealed
//!
//! Revealed: the set of intermediate VTXO outpoints, the public Pedersen
//! commitments at each hop, and the per-hop signer pubkeys. **Not**
//! revealed: amounts and blindings at intermediate hops — they are sent in
//! the [`PedersenOpening`] but only to the verifier the proof is shared
//! with. Senders/recipients beyond the chain itself are not exposed.
//!
//! # Relationship to `dark_core::compliance`
//!
//! `dark_core::compliance` (feature-gated behind `compliance-proofs`) has
//! an earlier `SourceOfFundsProof` that proves the *commitment-path
//! prefix* between two VTXOs of the same owner. That construction reveals
//! only the public commitment txids and signs the prefix with the owner's
//! key. It is a strict subset of what the present module does:
//!
//! - this module operates one layer down, on Pedersen commitment openings;
//! - it covers multi-owner chains (each hop is signed by its own owner);
//! - it explicitly anchors against an allowlist of [`SourceLink`] roots
//!   (on-chain UTXOs *or* Ark round commitments), which the path-prefix
//!   construction does not model.
//!
//! Both can coexist; the dark-core variant remains useful for
//! single-owner audits where path prefixing is sufficient.

use bitcoin::secp256k1::{
    self,
    hashes::{sha256, Hash, HashEngine},
    schnorr::Signature,
    Keypair, Message, Secp256k1, XOnlyPublicKey,
};
use secp256k1::Scalar;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::commitment::PedersenCommitment;

/// Domain-separation tag for source-of-funds proofs.
///
/// Mixed into every per-hop signature digest and into the proof-level
/// `transcript_hash` to prevent cross-protocol transcript reuse.
pub const SOURCE_OF_FUNDS_DST: &[u8] = b"dark-disclosure/source-of-funds/v1";

/// Errors returned by [`prove_source_of_funds`] and [`verify_source_of_funds`].
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DisclosureError {
    /// Proof structure is malformed (empty chain, wrong-length signature, ...).
    #[error("invalid proof structure: {0}")]
    InvalidStructure(&'static str),
    /// Two adjacent hops disagreed on the seam outpoint or commitment.
    #[error("chain discontinuity between hops {from} and {to}")]
    ChainDiscontinuity {
        /// Index of the earlier hop.
        from: usize,
        /// Index of the later hop.
        to: usize,
    },
    /// The proof's first input does not match any allowed source root.
    #[error("chain root is not in the allowed source set")]
    RootNotAllowed,
    /// The proof's last output does not match the subject VTXO.
    #[error("proof does not terminate at the subject VTXO")]
    ChainDoesNotTerminateAtVtxo,
    /// A per-hop Schnorr signature failed verification.
    #[error("invalid hop signature at hop {hop}")]
    InvalidHopSignature {
        /// Zero-based index of the offending hop.
        hop: usize,
    },
    /// The recomputed `transcript_hash` did not match the proof's claim.
    #[error("transcript hash mismatch")]
    TranscriptMismatch,
    /// The opening chain or hop index references a position that does not
    /// exist (e.g. the prover supplied an empty `opening_chain`).
    #[error("empty chain")]
    EmptyChain,
    /// A cryptographic primitive returned an error while building the proof.
    #[error("crypto error: {0}")]
    Crypto(&'static str),
}

/// Outpoint of a confidential VTXO inside a chain hop.
///
/// Defined locally so `dark-confidential` does not have to reach into
/// `dark-core::domain` for a value-only identifier. The `txid` is the
/// hex-encoded Bitcoin txid; `vout` is the output index.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VtxoOutpoint {
    /// Hex-encoded transaction id of the confidential transaction that
    /// produced this VTXO.
    pub txid: String,
    /// Output index inside that transaction.
    pub vout: u32,
}

impl VtxoOutpoint {
    /// Construct a new [`VtxoOutpoint`].
    pub fn new(txid: impl Into<String>, vout: u32) -> Self {
        Self {
            txid: txid.into(),
            vout,
        }
    }

    fn write_into(&self, engine: &mut sha256::HashEngine) {
        let txid_bytes = self.txid.as_bytes();
        engine.input(&(txid_bytes.len() as u32).to_be_bytes());
        engine.input(txid_bytes);
        engine.input(&self.vout.to_be_bytes());
    }
}

/// Allowed root for a source-of-funds proof.
///
/// Each [`SourceLink`] is a typed tag identifying a "where the money
/// came from" anchor that the verifier is willing to trust as a chain
/// origin: either a confirmed on-chain UTXO (e.g. a deposit boarding
/// the Ark) or the commitment txid of an Ark round (so VTXOs minted by
/// that round inherit the round's compliance status).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceLink {
    /// An on-chain UTXO that funded entry into the system.
    OnChainUtxo {
        /// Hex-encoded txid of the funding transaction.
        txid: String,
        /// Output index of the funding output.
        vout: u32,
    },
    /// An Ark round whose commitment txid is treated as a fresh root.
    ArkRound {
        /// Hex-encoded round commitment txid.
        commitment_txid: String,
    },
}

impl SourceLink {
    /// Returns the [`VtxoOutpoint`] this source link expects to see as
    /// the first hop's `prev_outpoint`. For an Ark round, the `vout` is
    /// `0` by convention — the round commitment txid uniquely identifies
    /// the root and the first hop's output is the only meaningful child.
    pub fn expected_chain_root(&self) -> VtxoOutpoint {
        match self {
            SourceLink::OnChainUtxo { txid, vout } => VtxoOutpoint::new(txid.clone(), *vout),
            SourceLink::ArkRound { commitment_txid } => {
                VtxoOutpoint::new(commitment_txid.clone(), 0)
            }
        }
    }

    fn write_into(&self, engine: &mut sha256::HashEngine) {
        match self {
            SourceLink::OnChainUtxo { txid, vout } => {
                engine.input(&[0x01]);
                let txid_bytes = txid.as_bytes();
                engine.input(&(txid_bytes.len() as u32).to_be_bytes());
                engine.input(txid_bytes);
                engine.input(&vout.to_be_bytes());
            }
            SourceLink::ArkRound { commitment_txid } => {
                engine.input(&[0x02]);
                let txid_bytes = commitment_txid.as_bytes();
                engine.input(&(txid_bytes.len() as u32).to_be_bytes());
                engine.input(txid_bytes);
            }
        }
    }
}

/// Convenience marker for the chain origin: the same shape as a
/// [`VtxoOutpoint`], but distinct in name to clarify intent at call sites.
pub type ChainRoot = VtxoOutpoint;

/// Pedersen commitment opening: the (amount, blinding) pair that
/// re-creates a commitment via `commit(amount, blinding)`.
///
/// Sent only to the verifier the proof is being shared with. Treat the
/// `blinding` field as secret material outside that context.
///
/// The blinding scalar is wire-encoded as a 64-character hex string
/// (32-byte big-endian), matching the convention used elsewhere in the
/// dark stack (`dark_core::compliance`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenOpening {
    /// Plaintext amount in satoshis.
    pub amount: u64,
    /// Blinding scalar, hex-encoded (32 bytes big-endian).
    pub blinding_hex: String,
}

impl PedersenOpening {
    /// Construct a new opening from raw components.
    pub fn new(amount: u64, blinding: &Scalar) -> Self {
        Self {
            amount,
            blinding_hex: hex::encode(blinding.to_be_bytes()),
        }
    }

    /// Recompute the public Pedersen commitment for this opening.
    pub fn to_commitment(&self) -> Result<PedersenCommitment, DisclosureError> {
        let blinding = self.blinding_scalar()?;
        PedersenCommitment::commit(self.amount, &blinding)
            .map_err(|_| DisclosureError::Crypto("commitment reconstruction failed"))
    }

    fn blinding_scalar(&self) -> Result<Scalar, DisclosureError> {
        let bytes = decode_fixed_hex::<32>(&self.blinding_hex)
            .map_err(|_| DisclosureError::Crypto("opening blinding hex is malformed"))?;
        Scalar::from_be_bytes(bytes)
            .map_err(|_| DisclosureError::Crypto("opening blinding outside curve order"))
    }

    fn write_into(&self, engine: &mut sha256::HashEngine) -> Result<(), DisclosureError> {
        let blinding = self.blinding_scalar()?;
        engine.input(&self.amount.to_be_bytes());
        engine.input(&blinding.to_be_bytes());
        Ok(())
    }
}

/// One step of the linkable-graph chain.
///
/// `input_*` describes the VTXO consumed by the hop; `output_*` describes
/// the VTXO produced. The Schnorr `signature`, made by the holder of
/// `signer_pubkey`, binds this hop's transcript and prevents another
/// party from forging a link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopProof {
    /// Position of this hop in the chain (zero-based).
    pub hop_index: u32,
    /// VTXO consumed by the hop. Equals the previous hop's `next_outpoint`
    /// for `hop_index > 0`, and matches a [`SourceLink`] for `hop_index == 0`.
    pub prev_outpoint: VtxoOutpoint,
    /// VTXO produced by the hop. Equals the next hop's `prev_outpoint`
    /// for `hop_index < hops_count - 1`, and the proof's
    /// `vtxo_outpoint` for the final hop.
    pub next_outpoint: VtxoOutpoint,
    /// Opening of the Pedersen commitment on the input VTXO. Lets the
    /// verifier recompute the input commitment bytes.
    pub input_opening: PedersenOpening,
    /// Opening of the Pedersen commitment on the output VTXO.
    pub output_opening: PedersenOpening,
    /// X-only public key of the entity that signed this hop, hex-encoded
    /// (32 bytes).
    pub signer_pubkey_hex: String,
    /// BIP-340 Schnorr signature over `hop_signing_digest` for this
    /// hop, hex-encoded (64 bytes).
    pub signature_hex: String,
}

/// Source-of-funds proof shared with an auditor.
///
/// Combines the chain of [`HopProof`]s with the allowed-root metadata
/// (`source_set`) and a `transcript_hash` that ties everything together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceOfFundsProof {
    /// Outpoint of the subject VTXO whose source is being proven.
    pub vtxo_outpoint: VtxoOutpoint,
    /// Allowed roots the chain may anchor to. The first hop's
    /// `prev_outpoint` must match one of these.
    pub source_set: Vec<SourceLink>,
    /// Ordered chain of hops from a source root down to the subject VTXO.
    pub hop_proofs: Vec<HopProof>,
    /// 32-byte tagged-hash digest binding the entire proof.
    pub transcript_hash: [u8; 32],
}

/// Generate a source-of-funds proof for `vtxo`.
///
/// `opening_chain` lists the VTXOs visited by the chain in order from the
/// chain root toward (and including) the subject. Each entry is the
/// `(outpoint, opening)` pair for one VTXO. There must be at least two
/// entries: one for the chain root and one for the subject.
///
/// `roots` is the allow-list of permissible chain origins. The first
/// outpoint of `opening_chain` must match the
/// [`SourceLink::expected_chain_root`] of one of the entries in `roots`.
///
/// For each hop, `signer_secrets[i]` is the secret key of the owner of
/// `opening_chain[i].0` — the entity authorised to sign that link.
pub fn prove_source_of_funds(
    vtxo: &crate::vtxo::ConfidentialVtxo,
    opening_chain: &[(VtxoOutpoint, PedersenOpening)],
    roots: &[SourceLink],
    signer_secrets: &[secp256k1::SecretKey],
) -> Result<SourceOfFundsProof, DisclosureError> {
    if opening_chain.len() < 2 {
        return Err(DisclosureError::InvalidStructure(
            "opening_chain must contain at least a root and a subject entry",
        ));
    }
    if signer_secrets.len() != opening_chain.len() - 1 {
        return Err(DisclosureError::InvalidStructure(
            "signer_secrets must have exactly one entry per hop",
        ));
    }
    if roots.is_empty() {
        return Err(DisclosureError::InvalidStructure(
            "roots allow-list must be non-empty",
        ));
    }

    let vtxo_outpoint = confidential_vtxo_outpoint(vtxo);
    let chain_tail = &opening_chain[opening_chain.len() - 1].0;
    if chain_tail != &vtxo_outpoint {
        return Err(DisclosureError::ChainDoesNotTerminateAtVtxo);
    }

    let chain_root = &opening_chain[0].0;
    if !root_in_allowed_set(chain_root, roots) {
        return Err(DisclosureError::RootNotAllowed);
    }

    let transcript_hash = compute_transcript_hash(&vtxo_outpoint, roots, opening_chain)?;

    let secp = Secp256k1::new();
    let mut hop_proofs = Vec::with_capacity(opening_chain.len() - 1);
    for (index, window) in opening_chain.windows(2).enumerate() {
        let (prev_outpoint, input_opening) = &window[0];
        let (next_outpoint, output_opening) = &window[1];
        let signer_secret = &signer_secrets[index];

        let keypair = Keypair::from_secret_key(&secp, signer_secret);
        let signer_pubkey = XOnlyPublicKey::from_keypair(&keypair).0;
        let digest = hop_signing_digest(
            index as u32,
            prev_outpoint,
            next_outpoint,
            input_opening,
            output_opening,
            &signer_pubkey,
            &transcript_hash,
        )?;
        let message = Message::from_digest(digest);
        let signature = secp.sign_schnorr(&message, &keypair);

        hop_proofs.push(HopProof {
            hop_index: index as u32,
            prev_outpoint: prev_outpoint.clone(),
            next_outpoint: next_outpoint.clone(),
            input_opening: input_opening.clone(),
            output_opening: output_opening.clone(),
            signer_pubkey_hex: hex::encode(signer_pubkey.serialize()),
            signature_hex: hex::encode(signature.serialize()),
        });
    }

    Ok(SourceOfFundsProof {
        vtxo_outpoint,
        source_set: roots.to_vec(),
        hop_proofs,
        transcript_hash,
    })
}

/// Verify a [`SourceOfFundsProof`] against `vtxo` and `allowed_roots`.
///
/// The verifier walks the chain hop-by-hop, recomputing each commitment
/// from its opening, checking adjacency between hops, and verifying the
/// per-hop Schnorr signature. The chain must anchor at one of
/// `allowed_roots` and terminate at `vtxo`'s outpoint.
pub fn verify_source_of_funds(
    proof: &SourceOfFundsProof,
    vtxo: &crate::vtxo::ConfidentialVtxo,
    allowed_roots: &[SourceLink],
) -> Result<(), DisclosureError> {
    if proof.hop_proofs.is_empty() {
        return Err(DisclosureError::EmptyChain);
    }

    let expected_outpoint = confidential_vtxo_outpoint(vtxo);
    if proof.vtxo_outpoint != expected_outpoint {
        return Err(DisclosureError::ChainDoesNotTerminateAtVtxo);
    }

    let allowed_set: HashSet<&SourceLink> = allowed_roots.iter().collect();
    if !proof
        .source_set
        .iter()
        .all(|claimed| allowed_set.contains(claimed))
    {
        return Err(DisclosureError::RootNotAllowed);
    }

    let chain_root = &proof.hop_proofs[0].prev_outpoint;
    if !root_in_allowed_set(chain_root, allowed_roots) {
        return Err(DisclosureError::RootNotAllowed);
    }

    let chain_tail = &proof.hop_proofs[proof.hop_proofs.len() - 1].next_outpoint;
    if chain_tail != &expected_outpoint {
        return Err(DisclosureError::ChainDoesNotTerminateAtVtxo);
    }

    let opening_chain = opening_chain_from_hops(&proof.hop_proofs)?;
    let recomputed_transcript =
        compute_transcript_hash(&expected_outpoint, &proof.source_set, &opening_chain)?;
    if recomputed_transcript != proof.transcript_hash {
        return Err(DisclosureError::TranscriptMismatch);
    }

    let secp = Secp256k1::verification_only();
    for (index, hop) in proof.hop_proofs.iter().enumerate() {
        if hop.hop_index as usize != index {
            return Err(DisclosureError::InvalidStructure(
                "hop_index does not match the hop's position in the chain",
            ));
        }

        let expected_input = hop.input_opening.to_commitment()?;
        let expected_output = hop.output_opening.to_commitment()?;
        if index > 0 {
            let prev_hop = &proof.hop_proofs[index - 1];
            if prev_hop.next_outpoint != hop.prev_outpoint {
                return Err(DisclosureError::ChainDiscontinuity {
                    from: index - 1,
                    to: index,
                });
            }
            if prev_hop.output_opening.to_commitment()?.to_bytes() != expected_input.to_bytes() {
                return Err(DisclosureError::ChainDiscontinuity {
                    from: index - 1,
                    to: index,
                });
            }
        }
        // Touching the recomputed commitments here surfaces opening-side
        // errors before we get to signature verification.
        let _ = expected_input.to_bytes();
        let _ = expected_output.to_bytes();

        let signer_pubkey = decode_xonly(&hop.signer_pubkey_hex)
            .map_err(|_| DisclosureError::InvalidHopSignature { hop: index })?;
        let digest = hop_signing_digest(
            hop.hop_index,
            &hop.prev_outpoint,
            &hop.next_outpoint,
            &hop.input_opening,
            &hop.output_opening,
            &signer_pubkey,
            &proof.transcript_hash,
        )?;
        let signature_bytes: [u8; 64] = decode_fixed_hex(&hop.signature_hex)
            .map_err(|_| DisclosureError::InvalidHopSignature { hop: index })?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| DisclosureError::InvalidHopSignature { hop: index })?;
        let message = Message::from_digest(digest);
        secp.verify_schnorr(&signature, &message, &signer_pubkey)
            .map_err(|_| DisclosureError::InvalidHopSignature { hop: index })?;
    }

    Ok(())
}

fn decode_xonly(hex: &str) -> Result<XOnlyPublicKey, ()> {
    let bytes: [u8; 32] = decode_fixed_hex(hex)?;
    XOnlyPublicKey::from_slice(&bytes).map_err(|_| ())
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    let bytes = hex::decode(value).map_err(|_| ())?;
    if bytes.len() != N {
        return Err(());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn confidential_vtxo_outpoint(vtxo: &crate::vtxo::ConfidentialVtxo) -> VtxoOutpoint {
    VtxoOutpoint::new(vtxo.leaf_outpoint.txid.to_string(), vtxo.leaf_outpoint.vout)
}

fn root_in_allowed_set(chain_root: &VtxoOutpoint, roots: &[SourceLink]) -> bool {
    roots
        .iter()
        .any(|root| root.expected_chain_root() == *chain_root)
}

fn opening_chain_from_hops(
    hops: &[HopProof],
) -> Result<Vec<(VtxoOutpoint, PedersenOpening)>, DisclosureError> {
    let mut chain = Vec::with_capacity(hops.len() + 1);
    let first = hops.first().ok_or(DisclosureError::EmptyChain)?;
    chain.push((first.prev_outpoint.clone(), first.input_opening.clone()));
    for hop in hops {
        chain.push((hop.next_outpoint.clone(), hop.output_opening.clone()));
    }
    Ok(chain)
}

fn compute_transcript_hash(
    vtxo_outpoint: &VtxoOutpoint,
    roots: &[SourceLink],
    opening_chain: &[(VtxoOutpoint, PedersenOpening)],
) -> Result<[u8; 32], DisclosureError> {
    let mut engine = sha256::Hash::engine();
    let dst_digest = sha256::Hash::hash(SOURCE_OF_FUNDS_DST).to_byte_array();
    engine.input(&dst_digest);
    engine.input(&dst_digest);
    vtxo_outpoint.write_into(&mut engine);
    engine.input(&(roots.len() as u32).to_be_bytes());
    for root in roots {
        root.write_into(&mut engine);
    }
    engine.input(&(opening_chain.len() as u32).to_be_bytes());
    for (outpoint, opening) in opening_chain {
        outpoint.write_into(&mut engine);
        let commitment = opening.to_commitment()?;
        engine.input(&commitment.to_bytes());
    }
    Ok(sha256::Hash::from_engine(engine).to_byte_array())
}

fn hop_signing_digest(
    hop_index: u32,
    prev_outpoint: &VtxoOutpoint,
    next_outpoint: &VtxoOutpoint,
    input_opening: &PedersenOpening,
    output_opening: &PedersenOpening,
    signer_pubkey: &XOnlyPublicKey,
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32], DisclosureError> {
    let mut engine = sha256::Hash::engine();
    let dst_digest = sha256::Hash::hash(SOURCE_OF_FUNDS_DST).to_byte_array();
    engine.input(&dst_digest);
    engine.input(&dst_digest);
    engine.input(&hop_index.to_be_bytes());
    prev_outpoint.write_into(&mut engine);
    next_outpoint.write_into(&mut engine);
    input_opening.write_into(&mut engine)?;
    output_opening.write_into(&mut engine)?;
    engine.input(&signer_pubkey.serialize());
    engine.input(transcript_hash);
    Ok(sha256::Hash::from_engine(engine).to_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtxo::ConfidentialVtxo;
    use bitcoin::{OutPoint, Txid};
    use secp256k1::rand::{RngCore, SeedableRng};
    use secp256k1::{rand::rngs::SmallRng, SecretKey};

    /// Deterministic blinding from a u64 seed (avoids RNG flakiness in tests).
    fn blinding_from_seed(seed: u64) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&seed.to_be_bytes());
        Scalar::from_be_bytes(bytes).unwrap()
    }

    fn opening(amount: u64, seed: u64) -> PedersenOpening {
        PedersenOpening::new(amount, &blinding_from_seed(seed))
    }

    fn outpoint(label: &str, vout: u32) -> VtxoOutpoint {
        VtxoOutpoint::new(label.to_string(), vout)
    }

    fn signer_secret(seed: u8) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        // ensure non-zero by filling tail too
        bytes[31] = 0x01;
        SecretKey::from_slice(&bytes).expect("valid secret")
    }

    /// Build a `ConfidentialVtxo` whose `leaf_outpoint` round-trips
    /// through `confidential_vtxo_outpoint` to yield a stable string
    /// representation. The label is zero-padded into the 32-byte txid.
    fn target_vtxo_for(label: &str, vout: u32, opening: &PedersenOpening) -> ConfidentialVtxo {
        // Use 32 bytes derived from the label so Display(hex) round-trips
        // through `confidential_vtxo_outpoint`.
        let mut txid_bytes = [0u8; 32];
        for (i, b) in label.as_bytes().iter().enumerate().take(32) {
            txid_bytes[i] = *b;
        }
        let txid = Txid::from_byte_array(txid_bytes);
        let leaf_outpoint = OutPoint::new(txid, vout);
        let secp = Secp256k1::new();
        let dummy = Keypair::from_secret_key(&secp, &signer_secret(0));
        let pubkey = XOnlyPublicKey::from_keypair(&dummy).0;
        let blinding = opening.blinding_scalar().unwrap();
        ConfidentialVtxo::new(opening.amount, blinding, pubkey, leaf_outpoint, 144)
    }

    fn outpoint_matching(vtxo: &ConfidentialVtxo) -> VtxoOutpoint {
        VtxoOutpoint::new(vtxo.leaf_outpoint.txid.to_string(), vtxo.leaf_outpoint.vout)
    }

    /// Test fixture bundling the inputs to `prove_source_of_funds` plus
    /// the matching subject VTXO.
    struct ChainFixture {
        chain: Vec<(VtxoOutpoint, PedersenOpening)>,
        roots: Vec<SourceLink>,
        signers: Vec<SecretKey>,
        subject: ConfidentialVtxo,
    }

    /// Build the canonical 3-hop chain used by several tests.
    fn build_three_hop_chain() -> ChainFixture {
        let subject_opening = opening(900, 0xdead);
        let subject_vtxo = target_vtxo_for("subject", 1, &subject_opening);
        let subject_outpoint = outpoint_matching(&subject_vtxo);

        let root_outpoint = outpoint("rootutxo000000000000000000000000", 0);
        let mid1 = opening(1000, 100);
        let mid2 = opening(950, 200);

        let chain = vec![
            (root_outpoint.clone(), opening(1000, 1)),
            (outpoint("hop1vtxo000000000000000000000000", 0), mid1),
            (outpoint("hop2vtxo000000000000000000000000", 0), mid2),
            (subject_outpoint, subject_opening),
        ];

        let roots = vec![SourceLink::OnChainUtxo {
            txid: root_outpoint.txid.clone(),
            vout: 0,
        }];

        let signers = vec![signer_secret(11), signer_secret(22), signer_secret(33)];

        ChainFixture {
            chain,
            roots,
            signers,
            subject: subject_vtxo,
        }
    }

    #[test]
    fn three_hop_chain_round_trip() {
        let ChainFixture {
            chain,
            roots,
            signers,
            subject,
        } = build_three_hop_chain();
        let proof = prove_source_of_funds(&subject, &chain, &roots, &signers).expect("prove");

        assert_eq!(proof.hop_proofs.len(), 3);
        assert_eq!(proof.vtxo_outpoint, outpoint_matching(&subject));
        verify_source_of_funds(&proof, &subject, &roots).expect("verify ok");
    }

    #[test]
    fn ark_round_root_round_trip() {
        let subject_opening = opening(500, 0xbeef);
        let subject = target_vtxo_for("ark-round-subject", 0, &subject_opening);
        let subject_outpoint = outpoint_matching(&subject);
        let round_txid = "arkround0000000000000000000000000".to_string();
        let chain = vec![
            (VtxoOutpoint::new(round_txid.clone(), 0), opening(500, 7)),
            (subject_outpoint.clone(), subject_opening),
        ];
        let roots = vec![SourceLink::ArkRound {
            commitment_txid: round_txid,
        }];
        let signers = vec![signer_secret(99)];

        let proof = prove_source_of_funds(&subject, &chain, &roots, &signers).expect("prove");
        verify_source_of_funds(&proof, &subject, &roots).expect("verify ok");
    }

    #[test]
    fn broken_hop_signature_is_rejected() {
        let ChainFixture {
            chain,
            roots,
            signers,
            subject,
        } = build_three_hop_chain();
        let mut proof = prove_source_of_funds(&subject, &chain, &roots, &signers).expect("prove");

        // Flip a single bit in the middle hop's signature.
        let mut sig_bytes: [u8; 64] = decode_fixed_hex(&proof.hop_proofs[1].signature_hex).unwrap();
        sig_bytes[5] ^= 0x01;
        proof.hop_proofs[1].signature_hex = hex::encode(sig_bytes);

        let err = verify_source_of_funds(&proof, &subject, &roots).unwrap_err();
        assert!(matches!(
            err,
            DisclosureError::InvalidHopSignature { hop: 1 }
        ));
    }

    #[test]
    fn root_not_in_allowed_set_is_rejected() {
        let ChainFixture {
            chain,
            roots,
            signers,
            subject,
        } = build_three_hop_chain();
        let proof = prove_source_of_funds(&subject, &chain, &roots, &signers).expect("prove");

        let unrelated = vec![SourceLink::OnChainUtxo {
            txid: "decoyutxo000000000000000000000000".to_string(),
            vout: 0,
        }];
        let err = verify_source_of_funds(&proof, &subject, &unrelated).unwrap_err();
        assert_eq!(err, DisclosureError::RootNotAllowed);
    }

    #[test]
    fn replayed_hop_proof_is_rejected() {
        // Build two unrelated chains that share a signer at hop index 1
        // but have different transcripts. Splicing hop 1 from chain A
        // into chain B must fail because the transcript_hash differs.
        let ChainFixture {
            chain: chain_a,
            roots: roots_a,
            signers: signers_a,
            subject: subject_a,
        } = build_three_hop_chain();
        let proof_a =
            prove_source_of_funds(&subject_a, &chain_a, &roots_a, &signers_a).expect("prove A");

        // Build chain B with a different subject and root but reuse the
        // signer at index 1, so the attacker has a real signature on a
        // hop-1 transcript that does NOT belong to chain B.
        let subject_b_opening = opening(700, 0xcafe);
        let subject_b = target_vtxo_for("subject-b", 1, &subject_b_opening);
        let subject_b_outpoint = outpoint_matching(&subject_b);
        let root_b = outpoint("rootutxo-b00000000000000000000000", 0);

        let chain_b = vec![
            (root_b.clone(), opening(700, 9)),
            (
                outpoint("hop1vtxo-b00000000000000000000000", 0),
                opening(700, 90),
            ),
            (
                outpoint("hop2vtxo-b00000000000000000000000", 0),
                opening(700, 91),
            ),
            (subject_b_outpoint, subject_b_opening),
        ];
        let roots_b = vec![SourceLink::OnChainUtxo {
            txid: root_b.txid.clone(),
            vout: 0,
        }];
        let signers_b = vec![
            signer_secret(11),
            signers_a[1], // shared signer at index 1
            signer_secret(33),
        ];
        let mut proof_b =
            prove_source_of_funds(&subject_b, &chain_b, &roots_b, &signers_b).expect("prove B");

        // Splice hop 1 from chain A into chain B. The transcript_hash on
        // proof_b is still chain B's, so the replayed signature must fail.
        proof_b.hop_proofs[1].signature_hex = proof_a.hop_proofs[1].signature_hex.clone();
        proof_b.hop_proofs[1].input_opening = proof_a.hop_proofs[1].input_opening.clone();
        proof_b.hop_proofs[1].output_opening = proof_a.hop_proofs[1].output_opening.clone();
        proof_b.hop_proofs[1].prev_outpoint = proof_a.hop_proofs[1].prev_outpoint.clone();
        proof_b.hop_proofs[1].next_outpoint = proof_a.hop_proofs[1].next_outpoint.clone();
        proof_b.hop_proofs[1].signer_pubkey_hex = proof_a.hop_proofs[1].signer_pubkey_hex.clone();

        let err = verify_source_of_funds(&proof_b, &subject_b, &roots_b).unwrap_err();
        // The chain becomes discontinuous OR the transcript fails to
        // recompute identically — either is a clear rejection of the
        // replayed hop.
        assert!(
            matches!(
                err,
                DisclosureError::ChainDiscontinuity { .. }
                    | DisclosureError::TranscriptMismatch
                    | DisclosureError::InvalidHopSignature { .. }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn empty_chain_is_rejected_at_prove_time() {
        let subject_opening = opening(1, 1);
        let subject = target_vtxo_for("subject-empty", 0, &subject_opening);
        let roots = vec![SourceLink::OnChainUtxo {
            txid: "x".to_string(),
            vout: 0,
        }];
        let err = prove_source_of_funds(&subject, &[], &roots, &[]).unwrap_err();
        assert_eq!(
            err,
            DisclosureError::InvalidStructure(
                "opening_chain must contain at least a root and a subject entry"
            )
        );
    }

    #[test]
    fn discontinuous_chain_is_rejected_by_verifier() {
        let ChainFixture {
            chain,
            roots,
            signers,
            subject,
        } = build_three_hop_chain();
        let mut proof = prove_source_of_funds(&subject, &chain, &roots, &signers).expect("prove");

        // Tamper: alter hop[2].input_opening so it no longer matches
        // hop[1].output_opening. The signer's signature is still over
        // the *original* digest, so the digest will mismatch and we'll
        // surface a chain discontinuity (the verifier detects the
        // commitment break before it ever validates the signature).
        proof.hop_proofs[2].input_opening = opening(1234, 9999);
        // The transcript_hash field still points at the original chain,
        // so the inserted opening will not match anything and the
        // verifier should reject.
        let err = verify_source_of_funds(&proof, &subject, &roots).unwrap_err();
        assert!(
            matches!(
                err,
                DisclosureError::ChainDiscontinuity { .. }
                    | DisclosureError::TranscriptMismatch
                    | DisclosureError::InvalidHopSignature { .. }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn dst_is_pinned() {
        // Pin the on-disk constant so we notice accidental edits.
        assert_eq!(SOURCE_OF_FUNDS_DST, b"dark-disclosure/source-of-funds/v1");
    }

    #[test]
    fn random_blindings_round_trip() {
        // Regression net for blinding values that don't slot into our
        // u64-derived helper (use a wider distribution).
        let mut rng = SmallRng::seed_from_u64(42);
        let mut blinding = [0u8; 32];
        loop {
            rng.fill_bytes(&mut blinding);
            // Skip blindings outside the secp256k1 group order
            if Scalar::from_be_bytes(blinding).is_ok() {
                break;
            }
        }
        let blinding_scalar = Scalar::from_be_bytes(blinding).unwrap();
        let subject_opening = PedersenOpening::new(2_500, &blinding_scalar);
        let subject = target_vtxo_for("rng-subject", 0, &subject_opening);
        let subject_outpoint = outpoint_matching(&subject);

        let root_outpoint = outpoint("rng-root00000000000000000000000000", 0);
        let chain = vec![
            (root_outpoint.clone(), opening(2_500, 5)),
            (subject_outpoint, subject_opening),
        ];
        let roots = vec![SourceLink::OnChainUtxo {
            txid: root_outpoint.txid.clone(),
            vout: 0,
        }];
        let signers = vec![signer_secret(7)];

        let proof = prove_source_of_funds(&subject, &chain, &roots, &signers).expect("prove");
        verify_source_of_funds(&proof, &subject, &roots).expect("verify ok");
    }
}
