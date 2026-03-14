//! Asset domain models for token and NFT support on Ark.
//!
//! Aligned with Go arkd: `github.com/ark-network/ark/internal/core/domain/asset.go`

use serde::{Deserialize, Serialize};

/// Unique identifier for an asset (hex-encoded 32-byte hash).
pub type AssetId = String;

/// Asset type on the Ark network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetKind {
    /// Native Bitcoin satoshis (default).
    #[default]
    Bitcoin,
    /// Fungible token with a fixed supply.
    Token {
        /// Unique asset identifier
        asset_id: AssetId,
        /// Human-readable name
        name: String,
        /// Ticker symbol (e.g. "USDT")
        ticker: String,
        /// Decimal places for display
        decimals: u8,
        /// Total supply in base units
        total_supply: u64,
    },
    /// Non-fungible token.
    Nft {
        /// Unique asset identifier
        asset_id: AssetId,
        /// Human-readable name
        name: String,
        /// Optional URL to off-chain metadata (JSON)
        metadata_url: Option<String>,
    },
}

/// An amount denominated in a specific asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetAmount {
    /// Asset identifier — `None` means native Bitcoin.
    pub asset_id: Option<AssetId>,
    /// Amount in base units (sats for Bitcoin).
    pub amount: u64,
}

impl AssetAmount {
    /// Create a Bitcoin (satoshi) amount.
    pub fn bitcoin(sats: u64) -> Self {
        Self {
            asset_id: None,
            amount: sats,
        }
    }

    /// Create a token amount.
    pub fn token(asset_id: AssetId, amount: u64) -> Self {
        Self {
            asset_id: Some(asset_id),
            amount,
        }
    }

    /// Returns `true` if this is a native Bitcoin amount.
    pub fn is_bitcoin(&self) -> bool {
        self.asset_id.is_none()
    }
}

/// Asset registry entry — tracks known assets on this ASP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRecord {
    /// Unique asset identifier
    pub asset_id: AssetId,
    /// What kind of asset this is
    pub kind: AssetKind,
    /// Hex-encoded public key of the issuer
    pub issuer_pubkey: String,
    /// Unix timestamp when the asset was registered
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_amount_bitcoin() {
        let amt = AssetAmount::bitcoin(100_000);
        assert_eq!(amt.asset_id, None);
        assert_eq!(amt.amount, 100_000);
    }

    #[test]
    fn test_asset_amount_token() {
        let amt = AssetAmount::token("abc123".to_string(), 500);
        assert_eq!(amt.asset_id, Some("abc123".to_string()));
        assert_eq!(amt.amount, 500);
    }

    #[test]
    fn test_asset_amount_is_bitcoin() {
        assert!(AssetAmount::bitcoin(1).is_bitcoin());
        assert!(!AssetAmount::token("x".to_string(), 1).is_bitcoin());
    }

    #[test]
    fn test_asset_kind_serializes() {
        // Token round-trip
        let token = AssetKind::Token {
            asset_id: "aabbcc".to_string(),
            name: "TestToken".to_string(),
            ticker: "TT".to_string(),
            decimals: 8,
            total_supply: 21_000_000,
        };
        let json = serde_json::to_string(&token).unwrap();
        let deserialized: AssetKind = serde_json::from_str(&json).unwrap();
        assert_eq!(token, deserialized);

        // NFT round-trip
        let nft = AssetKind::Nft {
            asset_id: "ddeeff".to_string(),
            name: "CoolNFT".to_string(),
            metadata_url: Some("https://example.com/meta.json".to_string()),
        };
        let json = serde_json::to_string(&nft).unwrap();
        let deserialized: AssetKind = serde_json::from_str(&json).unwrap();
        assert_eq!(nft, deserialized);

        // Bitcoin round-trip
        let btc = AssetKind::Bitcoin;
        let json = serde_json::to_string(&btc).unwrap();
        let deserialized: AssetKind = serde_json::from_str(&json).unwrap();
        assert_eq!(btc, deserialized);
    }

    #[test]
    fn test_asset_record_serializes() {
        let record = AssetRecord {
            asset_id: "aabb".to_string(),
            kind: AssetKind::Bitcoin,
            issuer_pubkey: "deadbeef".to_string(),
            created_at: 1700000000,
        };
        let json = serde_json::to_string(&record).unwrap();
        let de: AssetRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(de.asset_id, "aabb");
        assert_eq!(de.created_at, 1700000000);
    }
}
