//! Static fee manager — returns a fixed fee rate (useful for dev/test).

use arkd_core::error::ArkResult;
use arkd_core::ports::{FeeManager, FeeStrategy};
use async_trait::async_trait;

/// A fee manager that always returns a fixed fee rate.
///
/// Useful for development, testing, and environments where dynamic
/// fee estimation is not needed.
#[derive(Debug, Clone)]
pub struct StaticFeeManager {
    /// Fixed fee rate in sat/vbyte
    fee_rate_sats_per_vb: u64,
}

impl StaticFeeManager {
    /// Create a new static fee manager with the given rate.
    pub fn new(fee_rate_sats_per_vb: u64) -> Self {
        Self {
            fee_rate_sats_per_vb,
        }
    }
}

#[async_trait]
impl FeeManager for StaticFeeManager {
    async fn estimate_fee_rate(&self, strategy: FeeStrategy) -> ArkResult<u64> {
        match strategy {
            FeeStrategy::Custom(rate) => Ok(rate),
            _ => Ok(self.fee_rate_sats_per_vb),
        }
    }

    async fn invalidate_cache(&self) -> ArkResult<()> {
        // No-op: static manager has no cache
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_fee_manager_returns_configured_rate() {
        let mgr = StaticFeeManager::new(5);
        let rate = mgr
            .estimate_fee_rate(FeeStrategy::Conservative)
            .await
            .unwrap();
        assert_eq!(rate, 5);
    }

    #[tokio::test]
    async fn test_static_fee_manager_conservative_equals_economical() {
        let mgr = StaticFeeManager::new(10);
        let conservative = mgr
            .estimate_fee_rate(FeeStrategy::Conservative)
            .await
            .unwrap();
        let economical = mgr
            .estimate_fee_rate(FeeStrategy::Economical)
            .await
            .unwrap();
        assert_eq!(conservative, economical);
    }

    #[tokio::test]
    async fn test_static_fee_manager_custom_returns_custom_value() {
        let mgr = StaticFeeManager::new(5);
        let rate = mgr
            .estimate_fee_rate(FeeStrategy::Custom(42))
            .await
            .unwrap();
        assert_eq!(rate, 42);
    }

    #[tokio::test]
    async fn test_fee_manager_cache_invalidation_noop() {
        let mgr = StaticFeeManager::new(7);
        mgr.invalidate_cache().await.unwrap();
        let rate = mgr
            .estimate_fee_rate(FeeStrategy::Economical)
            .await
            .unwrap();
        assert_eq!(rate, 7);
    }
}
