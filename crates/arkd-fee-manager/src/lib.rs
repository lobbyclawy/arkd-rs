//! Fee manager implementations for Ark protocol
//!
//! Provides static (fixed-rate) and Bitcoin Core RPC-based fee estimation.

pub mod bitcoin_core;
pub mod static_fee;

pub use bitcoin_core::BitcoinCoreFeeManager;
pub use static_fee::StaticFeeManager;

/// Convert BTC/kB fee rate to sat/vbyte.
///
/// Bitcoin Core returns fee rates in BTC/kB (1000 bytes).
/// 1 BTC = 100_000_000 sats, so BTC/kB * 100_000_000 / 1000 = BTC/kB * 100_000
pub fn btc_per_kb_to_sat_per_vbyte(btc_per_kb: f64) -> u64 {
    (btc_per_kb * 100_000.0).round() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_btc_per_kb_to_sat_per_vbyte_conversion() {
        // 0.00001 BTC/kB = 1 sat/vbyte
        assert_eq!(btc_per_kb_to_sat_per_vbyte(0.00001), 1);
        // 0.0001 BTC/kB = 10 sat/vbyte
        assert_eq!(btc_per_kb_to_sat_per_vbyte(0.0001), 10);
        // 0.001 BTC/kB = 100 sat/vbyte
        assert_eq!(btc_per_kb_to_sat_per_vbyte(0.001), 100);
        // 0.00002 BTC/kB = 2 sat/vbyte
        assert_eq!(btc_per_kb_to_sat_per_vbyte(0.00002), 2);
        // Zero
        assert_eq!(btc_per_kb_to_sat_per_vbyte(0.0), 0);
    }
}
