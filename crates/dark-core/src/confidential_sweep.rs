//! Confidential VTXO sweep helpers (#549).
//!
//! Confidential VTXOs (#530) carry their amount as a Pedersen commitment rather
//! than a plaintext satoshi value. When such a VTXO's CSV expires without being
//! unrolled, the operator sweeps it back via the same flow as a transparent
//! VTXO — but the witness must *open the commitment* so on-chain validators
//! (and audit tooling) can verify that the operator's recovered amount matches
//! the commitment that was originally locked into the tree.
//!
//! This module provides the small, testable plumbing that bridges the
//! [`crate::sweeper::Sweeper`] / [`crate::sweep::TxBuilderSweepService`] cycles
//! to the (still-stubbed) confidential exit-script builder from #547. The
//! transparent path is untouched: callers that pass a transparent
//! [`Vtxo`] get exactly the [`SweepInput`] they got before this module existed.
//!
//! # Hook point
//! `Sweeper::sweep_expired` (in [`crate::sweeper`]) and
//! `TxBuilderSweepService::sweep_expired_vtxos` (in [`crate::sweep`]) both
//! dispatch on [`Vtxo::is_confidential`] when constructing the per-VTXO
//! [`SweepInput`]. Selection, broadcast, and mark-as-swept logic is shared.
//!
//! # Stubs
//! [`build_confidential_exit_script`] is the #547 entry point. Until #547
//! lands on `main`, we provide a minimal stub with the expected signature so
//! the sweep wiring compiles and is exercised by tests. The stub returns the
//! commitment opening as an opaque "tapscript" string; the real builder will
//! produce a Bitcoin script that validates the opening on-chain.

use crate::domain::Vtxo;
use crate::error::{ArkError, ArkResult};
use crate::ports::SweepInput;

/// Opening data needed to spend the confidential exit leaf.
///
/// Matches the data the operator must reveal when sweeping a confidential
/// VTXO so that validators can recompute the Pedersen commitment from the
/// claimed amount and blinding factor.
///
/// # Fields
/// - `amount`: plaintext satoshi value the operator claims to recover. The
///   commitment built from `(amount, blinding)` must equal the VTXO's
///   `amount_commitment`.
/// - `blinding`: 32-byte Pedersen blinding factor that opens the commitment.
///   For unilateral operator-initiated sweeps the operator learns this from
///   the commitment-opening protocol agreed at VTXO creation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialOpening {
    /// Recovered amount in satoshis.
    pub amount: u64,
    /// 32-byte Pedersen blinding factor.
    pub blinding: [u8; 32],
}

impl ConfidentialOpening {
    /// Construct a new opening from `(amount, blinding)`.
    pub fn new(amount: u64, blinding: [u8; 32]) -> Self {
        Self { amount, blinding }
    }
}

/// Stub for the confidential exit-script builder (issue #547).
///
/// In the final implementation this returns a tapscript that:
/// 1. Verifies the revealed `(amount, blinding)` matches the leaf's Pedersen
///    commitment.
/// 2. Enforces the CSV-expiry timelock that gates the operator's sweep path.
/// 3. Pushes the operator's signature for the recovered output.
///
/// Until #547 lands we return a deterministic placeholder string that encodes
/// the commitment + amount + blinding so downstream code (PSBT builder,
/// witness encoder) and tests can wire end-to-end. The placeholder is
/// distinguishable from any valid Bitcoin script so it cannot be silently
/// broadcast.
///
/// # TODO(#547)
/// Replace this with the real tapscript builder from `dark-bitcoin`.
pub fn build_confidential_exit_script(
    amount_commitment: &[u8; 33],
    opening: &ConfidentialOpening,
) -> ArkResult<String> {
    // Defensive sanity check: a fully-zero commitment is not a valid secp256k1
    // point, so reject it early. The real builder will do full point
    // validation; this keeps the stub harmless if accidentally invoked on
    // garbage input.
    if amount_commitment.iter().all(|b| *b == 0) {
        return Err(ArkError::Internal(
            "confidential exit script: zero commitment".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(33 + 8 + 32 + 16);
    bytes.extend_from_slice(b"CONF_EXIT_STUB:");
    bytes.extend_from_slice(amount_commitment);
    bytes.extend_from_slice(&opening.amount.to_be_bytes());
    bytes.extend_from_slice(&opening.blinding);
    Ok(hex::encode(bytes))
}

/// Build the [`SweepInput`] for an expired confidential VTXO.
///
/// The transparent and confidential paths share everything except the witness
/// construction. The transparent path puts an empty `tapscripts` Vec and lets
/// the [`crate::ports::TxBuilder`] derive scripts from the tree; the
/// confidential path injects the exit-script (from #547) plus the commitment
/// opening so the witness can prove the recovered amount matches the
/// originally-committed value.
///
/// # Errors
/// Returns an error if `vtxo` is not a confidential VTXO. Callers that want
/// the unified path should use [`sweep_input_for_vtxo`].
pub fn build_confidential_sweep_input(
    vtxo: &Vtxo,
    opening: &ConfidentialOpening,
) -> ArkResult<SweepInput> {
    let payload = vtxo.confidential.as_ref().ok_or_else(|| {
        ArkError::Internal(format!(
            "build_confidential_sweep_input: vtxo {} is transparent",
            vtxo.outpoint
        ))
    })?;

    let exit_script = build_confidential_exit_script(&payload.amount_commitment, opening)?;

    Ok(SweepInput {
        txid: vtxo.outpoint.txid.clone(),
        vout: vtxo.outpoint.vout,
        // The on-chain UTXO carries the operator-known amount (i.e. the value
        // locked in the tree leaf). For confidential VTXOs this is conveyed
        // via the opening — the operator never used the plaintext `amount`
        // field. See issue #549 §"Verify that the sweep transaction
        // accounting is correct even when individual VTXO amounts are
        // unknown — the operator knows the UTXO amount from L1".
        amount: opening.amount,
        tapscripts: vec![exit_script],
        pubkey: vtxo.pubkey.clone(),
    })
}

/// Build a [`SweepInput`] for any [`Vtxo`], dispatching on its variant.
///
/// - **Transparent**: returns an input with empty `tapscripts` (the
///   [`crate::ports::TxBuilder`] resolves scripts from the tree, matching the
///   pre-#549 behavior).
/// - **Confidential**: requires `opening` to be `Some(_)`. Builds the exit
///   script via [`build_confidential_exit_script`] (#547 stub) and threads
///   the commitment opening through to the witness.
///
/// # Errors
/// - Returns an error if the VTXO is confidential but no opening was
///   provided. Callers MUST refuse to sweep confidential VTXOs without an
///   opening — silently using zero would let the operator steal funds.
pub fn sweep_input_for_vtxo(
    vtxo: &Vtxo,
    opening: Option<&ConfidentialOpening>,
) -> ArkResult<SweepInput> {
    if vtxo.is_confidential() {
        let opening = opening.ok_or_else(|| {
            ArkError::Internal(format!(
                "sweep_input_for_vtxo: confidential vtxo {} requires an opening",
                vtxo.outpoint
            ))
        })?;
        build_confidential_sweep_input(vtxo, opening)
    } else {
        Ok(SweepInput {
            txid: vtxo.outpoint.txid.clone(),
            vout: vtxo.outpoint.vout,
            amount: vtxo.amount,
            tapscripts: Vec::new(),
            pubkey: vtxo.pubkey.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vtxo::{ConfidentialPayload, Vtxo, VtxoOutpoint};

    fn make_payload(seed: u8) -> ConfidentialPayload {
        let mut commitment = [0u8; 33];
        commitment[0] = 0x02;
        commitment[1] = seed.max(1);
        ConfidentialPayload::new(commitment, vec![0xab; 8], [seed; 32], {
            let mut e = [0u8; 33];
            e[0] = 0x03;
            e[1] = seed;
            e
        })
    }

    fn make_confidential_vtxo(seed: u8) -> Vtxo {
        Vtxo::new_confidential(
            VtxoOutpoint::new(format!("conf_tx_{seed}"), u32::from(seed)),
            "deadbeef".to_string(),
            make_payload(seed),
        )
    }

    fn make_transparent_vtxo() -> Vtxo {
        Vtxo::new(
            VtxoOutpoint::new("plain_tx".to_string(), 1),
            42_000,
            "deadbeef".to_string(),
        )
    }

    #[test]
    fn build_exit_script_encodes_inputs() {
        let mut commitment = [0u8; 33];
        commitment[0] = 0x02;
        commitment[1] = 0x11;
        let opening = ConfidentialOpening::new(50_000, [0xcd; 32]);
        let script = build_confidential_exit_script(&commitment, &opening).unwrap();

        // Stub layout: prefix + commitment + amount(BE u64) + blinding
        assert!(script.starts_with(&hex::encode(b"CONF_EXIT_STUB:")));
        assert!(script.contains(&hex::encode(commitment)));
        assert!(script.contains(&hex::encode(50_000u64.to_be_bytes())));
        assert!(script.contains(&hex::encode([0xcd; 32])));
    }

    #[test]
    fn build_exit_script_rejects_zero_commitment() {
        let commitment = [0u8; 33];
        let opening = ConfidentialOpening::new(1, [0; 32]);
        let err = build_confidential_exit_script(&commitment, &opening).unwrap_err();
        assert!(err.to_string().contains("zero commitment"));
    }

    #[test]
    fn confidential_input_carries_opening() {
        let vtxo = make_confidential_vtxo(7);
        let opening = ConfidentialOpening::new(75_000, [0x42; 32]);
        let input = build_confidential_sweep_input(&vtxo, &opening).unwrap();

        assert_eq!(input.txid, vtxo.outpoint.txid);
        assert_eq!(input.vout, vtxo.outpoint.vout);
        assert_eq!(input.amount, opening.amount);
        assert_eq!(input.tapscripts.len(), 1);
        assert_eq!(input.pubkey, vtxo.pubkey);

        // Witness script must contain the commitment + opening
        let payload = vtxo.confidential.as_ref().unwrap();
        let script = &input.tapscripts[0];
        assert!(script.contains(&hex::encode(payload.amount_commitment)));
        assert!(script.contains(&hex::encode(75_000u64.to_be_bytes())));
        assert!(script.contains(&hex::encode([0x42; 32])));
    }

    #[test]
    fn confidential_input_rejects_transparent_vtxo() {
        let vtxo = make_transparent_vtxo();
        let opening = ConfidentialOpening::new(1, [0; 32]);
        let err = build_confidential_sweep_input(&vtxo, &opening).unwrap_err();
        assert!(err.to_string().contains("is transparent"));
    }

    #[test]
    fn dispatch_transparent_uses_legacy_path() {
        let vtxo = make_transparent_vtxo();
        let input = sweep_input_for_vtxo(&vtxo, None).unwrap();

        // Legacy invariants: empty tapscripts, plaintext amount, original pubkey
        assert!(
            input.tapscripts.is_empty(),
            "transparent path must keep tapscripts empty"
        );
        assert_eq!(input.amount, vtxo.amount);
        assert_eq!(input.txid, vtxo.outpoint.txid);
        assert_eq!(input.vout, vtxo.outpoint.vout);
        assert_eq!(input.pubkey, vtxo.pubkey);
    }

    #[test]
    fn dispatch_confidential_with_opening_returns_confidential_input() {
        let vtxo = make_confidential_vtxo(3);
        let opening = ConfidentialOpening::new(11_111, [0xee; 32]);
        let input = sweep_input_for_vtxo(&vtxo, Some(&opening)).unwrap();
        assert_eq!(input.amount, 11_111);
        assert_eq!(input.tapscripts.len(), 1);
    }

    #[test]
    fn dispatch_confidential_without_opening_errors() {
        let vtxo = make_confidential_vtxo(5);
        let err = sweep_input_for_vtxo(&vtxo, None).unwrap_err();
        assert!(err.to_string().contains("requires an opening"));
    }
}
