//! arkd-client — gRPC client library for arkd-rs.
//!
//! Provides a typed Rust client for the Ark protocol server.
//!
//! # Example
//!
//! ```no_run
//! use arkd_client::ArkClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut client = ArkClient::new("http://localhost:50051");
//!     client.connect().await?;
//!
//!     let info = client.get_info().await?;
//!     println!("Server: {} ({})", info.pubkey, info.network);
//!
//!     let vtxos = client.list_vtxos("02abc...").await?;
//!     for vtxo in vtxos {
//!         println!("VTXO: {} ({} sats)", vtxo.id, vtxo.amount);
//!     }
//!
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod error;
pub mod types;

pub use client::{ArkClient, OffchainTxResult, RedeemBranch};
pub use error::{ClientError, ClientResult};
pub use types::{
    Asset, AssetMetadata, Balance, BatchEvent, BatchTxRes, BoardingAddress, ControlAssetOption,
    ExistingControlAsset, Intent, IssueAssetResult, LockedAmount, NewControlAsset, OffchainAddress,
    OffchainBalance, OnchainBalance, RoundInfo, RoundSummary, ServerInfo, TxEvent, TxResult, Vtxo,
};
