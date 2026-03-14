//! Blockchain scanner implementations for on-chain VTXO watching.
//!
//! Provides two implementations of `BlockchainScanner`:
//! - [`NoopScanner`] — does nothing, for dev/test environments
//! - [`EsploraScanner`] — polls an Esplora HTTP API for script spends

pub mod esplora;
pub mod noop;

pub use esplora::EsploraScanner;
pub use noop::NoopScanner;

// Re-export the trait and event type for convenience
pub use arkd_core::ports::{BlockchainScanner, ScriptSpentEvent};
