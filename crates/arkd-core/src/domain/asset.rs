//! Asset domain types for token and NFT support on Ark.
//!
//! Mirrors Go arkd `internal/core/domain/asset.go`.

use serde::{Deserialize, Serialize};

/// Unique identifier for an asset (opaque string, e.g. hex-encoded).
pub type AssetId = String;

/// The kind of asset carried by a VTXO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    /// Plain bitcoin satoshis (the default).
    Bitcoin,
    /// Fungible token (e.g. stablecoin, governance token).
    Token,
    /// Non-fungible token (unique collectible / deed).
    Nft,
}

impl Default for AssetKind {
    fn default() -> Self {
        Self::Bitcoin
    }
}

/// A specific quantity of an asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetAmount {
    /// Which asset this amount refers to.
    pub asset_id: AssetId,
    /// The kind of asset.
    pub kind: AssetKind,
    /// Quantity (sats for Bitcoin, smallest unit for tokens, 1 for NFTs).
    pub value: u64,
}

impl AssetAmount {
    /// Create a new `AssetAmount`.
    pub fn new(asset_id: AssetId, kind: AssetKind, value: u64) -> Self {
        Self {
            asset_id,
            kind,
            value,
        }
    }

    /// Shorthand for a bitcoin amount.
    pub fn bitcoin(sats: u64) -> Self {
        Self {
            asset_id: "btc".to_string(),
            kind: AssetKind::Bitcoin,
            value: sats,
        }
    }
}

/// Persistent record of an asset registered in the system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRecord {
    /// Unique asset identifier.
    pub id: AssetId,
    /// Human-readable name (e.g. "LabCoin").
    pub name: String,
    /// Asset kind.
    pub kind: AssetKind,
    /// Total supply (0 means uncapped / not yet minted).
    pub total_supply: u64,
    /// Arbitrary metadata encoded as JSON string.
    #[serde(default)]
    pub metadata: String,
}

impl AssetRecord {
    /// Create a new `AssetRecord`.
    pub fn new(id: AssetId, name: String, kind: AssetKind, total_supply: u64) -> Self {
        Self {
            id,
            name,
            kind,
            total_supply,
            metadata: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_kind_default() {
        assert_eq!(AssetKind::default(), AssetKind::Bitcoin);
    }

    #[test]
    fn test_asset_amount_bitcoin() {
        let amt = AssetAmount::bitcoin(50_000);
        assert_eq!(amt.asset_id, "btc");
        assert_eq!(amt.kind, AssetKind::Bitcoin);
        assert_eq!(amt.value, 50_000);
    }

    #[test]
    fn test_asset_amount_token() {
        let amt = AssetAmount::new("usdt-001".into(), AssetKind::Token, 1_000_000);
        assert_eq!(amt.kind, AssetKind::Token);
        assert_eq!(amt.value, 1_000_000);
    }

    #[test]
    fn test_asset_record_serialization() {
        let rec = AssetRecord::new("nft-42".into(), "CoolNFT".into(), AssetKind::Nft, 1);
        let json = serde_json::to_string(&rec).unwrap();
        let deser: AssetRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, deser);
    }

    #[test]
    fn test_asset_record_metadata_default() {
        let json = r#"{"id":"x","name":"X","kind":"token","total_supply":100}"#;
        let rec: AssetRecord = serde_json::from_str(json).unwrap();
        assert_eq!(rec.metadata, "");
    }
}
