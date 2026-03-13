//! Input validation for the Ark protocol
//!
//! Centralised validation functions that reject malformed or out-of-range
//! inputs **before** they reach domain logic. Every public entry-point in
//! `ArkService` should call the appropriate validator.

use crate::error::{ArkError, ArkResult};

// ── Constants ────────────────────────────────────────────────────────

/// Absolute maximum number of VTXOs in a single request / round.
/// Prevents OOM from pathologically large batches.
pub const MAX_VTXO_COUNT: usize = 4096;

/// Maximum tree depth for VTXO Taproot trees.
/// A depth of 32 already supports 2^32 leaves — far beyond practical need.
pub const MAX_TREE_DEPTH: u32 = 32;

/// Minimum fee rate in sat/vB (below this, transactions won't propagate).
pub const MIN_FEE_RATE_SAT_VB: u64 = 1;

/// Maximum fee rate in sat/vB (sanity cap to avoid fee-sniping bugs).
pub const MAX_FEE_RATE_SAT_VB: u64 = 100_000;

/// Maximum amount in satoshis (21 million BTC).
pub const MAX_AMOUNT_SATS: u64 = 2_100_000_000_000_000;

/// Minimum timelock value in blocks (must be positive).
pub const MIN_TIMELOCK_BLOCKS: u32 = 1;

/// Maximum timelock in blocks (~10 years at 144 blocks/day).
pub const MAX_TIMELOCK_BLOCKS: u32 = 525_960;

/// Minimum timelock value in seconds (must be > LOCKTIME_THRESHOLD).
pub const MIN_TIMELOCK_SECONDS: u32 = 500_000_001;

/// Maximum timelock in seconds (~10 years from now is generous).
pub const MAX_TIMELOCK_SECONDS: u32 = 1_893_456_000; // ~2030-01-01

// ── Validators ───────────────────────────────────────────────────────

/// Validate a satoshi amount is within sane bounds.
pub fn validate_amount(amount: u64, context: &str) -> ArkResult<()> {
    if amount == 0 {
        return Err(ArkError::AmountTooSmall {
            amount: 0,
            minimum: 1,
        });
    }
    if amount > MAX_AMOUNT_SATS {
        return Err(ArkError::InvalidConfiguration(format!(
            "{context}: amount {amount} exceeds maximum {MAX_AMOUNT_SATS} sats"
        )));
    }
    Ok(())
}

/// Validate a hex-encoded public key (32-byte x-only or 33-byte compressed).
pub fn validate_pubkey_hex(hex_str: &str, context: &str) -> ArkResult<()> {
    if hex_str.is_empty() {
        return Err(ArkError::InvalidPublicKey(format!(
            "{context}: empty public key"
        )));
    }

    let bytes = hex::decode(hex_str)
        .map_err(|e| ArkError::InvalidPublicKey(format!("{context}: invalid hex encoding: {e}")))?;

    match bytes.len() {
        32 => {
            // x-only / Schnorr key
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&bytes).map_err(|e| {
                ArkError::InvalidPublicKey(format!("{context}: invalid x-only pubkey: {e}"))
            })?;
        }
        33 => {
            // Compressed SEC1 key
            bitcoin::secp256k1::PublicKey::from_slice(&bytes).map_err(|e| {
                ArkError::InvalidPublicKey(format!("{context}: invalid compressed pubkey: {e}"))
            })?;
        }
        other => {
            return Err(ArkError::InvalidPublicKey(format!(
                "{context}: expected 32 or 33 bytes, got {other}"
            )));
        }
    }

    Ok(())
}

/// Validate a transaction ID (64-char lowercase hex).
pub fn validate_txid(txid: &str, context: &str) -> ArkResult<()> {
    if txid.is_empty() {
        return Err(ArkError::Internal(format!("{context}: empty txid")));
    }
    if txid.len() != 64 {
        return Err(ArkError::Internal(format!(
            "{context}: txid must be 64 hex chars, got {}",
            txid.len()
        )));
    }
    if !txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ArkError::Internal(format!(
            "{context}: txid contains non-hex characters"
        )));
    }
    Ok(())
}

/// Validate VTXO count is within bounds.
pub fn validate_vtxo_count(count: usize, context: &str) -> ArkResult<()> {
    if count == 0 {
        return Err(ArkError::Internal(format!(
            "{context}: VTXO count must be > 0"
        )));
    }
    if count > MAX_VTXO_COUNT {
        return Err(ArkError::Internal(format!(
            "{context}: VTXO count {count} exceeds maximum {MAX_VTXO_COUNT}"
        )));
    }
    Ok(())
}

/// Validate tree depth is within safe bounds.
pub fn validate_tree_depth(depth: u32, context: &str) -> ArkResult<()> {
    if depth == 0 {
        return Err(ArkError::Internal(format!(
            "{context}: tree depth must be > 0"
        )));
    }
    if depth > MAX_TREE_DEPTH {
        return Err(ArkError::Internal(format!(
            "{context}: tree depth {depth} exceeds maximum {MAX_TREE_DEPTH}"
        )));
    }
    Ok(())
}

/// Validate a fee rate in sat/vB.
pub fn validate_fee_rate(sat_per_vb: u64, context: &str) -> ArkResult<()> {
    if sat_per_vb < MIN_FEE_RATE_SAT_VB {
        return Err(ArkError::Internal(format!(
            "{context}: fee rate {sat_per_vb} sat/vB below minimum {MIN_FEE_RATE_SAT_VB}"
        )));
    }
    if sat_per_vb > MAX_FEE_RATE_SAT_VB {
        return Err(ArkError::Internal(format!(
            "{context}: fee rate {sat_per_vb} sat/vB exceeds maximum {MAX_FEE_RATE_SAT_VB}"
        )));
    }
    Ok(())
}

/// Validate a block-height timelock value.
pub fn validate_timelock_blocks(blocks: u32, context: &str) -> ArkResult<()> {
    if blocks < MIN_TIMELOCK_BLOCKS {
        return Err(ArkError::Internal(format!(
            "{context}: timelock {blocks} blocks is below minimum {MIN_TIMELOCK_BLOCKS}"
        )));
    }
    if blocks > MAX_TIMELOCK_BLOCKS {
        return Err(ArkError::Internal(format!(
            "{context}: timelock {blocks} blocks exceeds maximum {MAX_TIMELOCK_BLOCKS}"
        )));
    }
    Ok(())
}

/// Validate an exit delay (the CSV relative timelock for unilateral exits).
pub fn validate_exit_delay(blocks: u32, context: &str) -> ArkResult<()> {
    // Exit delay uses CSV, which is a 16-bit field (max 65535).
    if blocks == 0 {
        return Err(ArkError::Internal(format!(
            "{context}: exit delay must be > 0"
        )));
    }
    if blocks > 65535 {
        return Err(ArkError::Internal(format!(
            "{context}: exit delay {blocks} exceeds CSV maximum 65535"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_amount_zero() {
        assert!(validate_amount(0, "test").is_err());
    }

    #[test]
    fn test_validate_amount_too_large() {
        assert!(validate_amount(MAX_AMOUNT_SATS + 1, "test").is_err());
    }

    #[test]
    fn test_validate_amount_valid() {
        assert!(validate_amount(546, "test").is_ok());
        assert!(validate_amount(MAX_AMOUNT_SATS, "test").is_ok());
    }

    #[test]
    fn test_validate_pubkey_hex_empty() {
        assert!(validate_pubkey_hex("", "test").is_err());
    }

    #[test]
    fn test_validate_pubkey_hex_invalid() {
        assert!(validate_pubkey_hex("not_hex", "test").is_err());
        assert!(validate_pubkey_hex("deadbeef", "test").is_err()); // wrong length
    }

    #[test]
    fn test_validate_pubkey_hex_valid_xonly() {
        // Valid x-only key (32 bytes)
        let pk = "0202020202020202020202020202020202020202020202020202020202020202";
        assert!(validate_pubkey_hex(pk, "test").is_ok());
    }

    #[test]
    fn test_validate_txid_valid() {
        let txid = "a".repeat(64);
        assert!(validate_txid(&txid, "test").is_ok());
    }

    #[test]
    fn test_validate_txid_invalid() {
        assert!(validate_txid("", "test").is_err());
        assert!(validate_txid("short", "test").is_err());
        assert!(validate_txid(&"g".repeat(64), "test").is_err()); // non-hex
    }

    #[test]
    fn test_validate_vtxo_count() {
        assert!(validate_vtxo_count(0, "test").is_err());
        assert!(validate_vtxo_count(MAX_VTXO_COUNT + 1, "test").is_err());
        assert!(validate_vtxo_count(1, "test").is_ok());
        assert!(validate_vtxo_count(MAX_VTXO_COUNT, "test").is_ok());
    }

    #[test]
    fn test_validate_tree_depth() {
        assert!(validate_tree_depth(0, "test").is_err());
        assert!(validate_tree_depth(MAX_TREE_DEPTH + 1, "test").is_err());
        assert!(validate_tree_depth(1, "test").is_ok());
        assert!(validate_tree_depth(MAX_TREE_DEPTH, "test").is_ok());
    }

    #[test]
    fn test_validate_fee_rate() {
        assert!(validate_fee_rate(0, "test").is_err());
        assert!(validate_fee_rate(MAX_FEE_RATE_SAT_VB + 1, "test").is_err());
        assert!(validate_fee_rate(1, "test").is_ok());
        assert!(validate_fee_rate(MAX_FEE_RATE_SAT_VB, "test").is_ok());
    }

    #[test]
    fn test_validate_timelock_blocks() {
        assert!(validate_timelock_blocks(0, "test").is_err());
        assert!(validate_timelock_blocks(MAX_TIMELOCK_BLOCKS + 1, "test").is_err());
        assert!(validate_timelock_blocks(1, "test").is_ok());
        assert!(validate_timelock_blocks(144, "test").is_ok());
    }

    #[test]
    fn test_validate_exit_delay() {
        assert!(validate_exit_delay(0, "test").is_err());
        assert!(validate_exit_delay(65536, "test").is_err());
        assert!(validate_exit_delay(1, "test").is_ok());
        assert!(validate_exit_delay(512, "test").is_ok());
        assert!(validate_exit_delay(65535, "test").is_ok());
    }
}
