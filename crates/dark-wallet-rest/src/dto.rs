//! Data-transfer objects exposed on the REST surface.
//!
//! These shadow a subset of [`dark_client::types`] with `utoipa::ToSchema`
//! derives so the OpenAPI spec carries rich type information. DTOs also
//! give us room to rename fields to REST-idiomatic casing without touching
//! the underlying gRPC types.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use dark_client::types::ServerInfo;

/// Server info response. Mirrors `ark.v1.GetInfoResponse`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ServerInfoDto {
    /// Server-signer x-only public key (hex).
    pub pubkey: String,
    /// Forfeit leaf public key (hex).
    pub forfeit_pubkey: String,
    /// Bitcoin network (`mainnet` | `testnet` | `signet` | `regtest`).
    pub network: String,
    /// Round session duration in seconds.
    pub session_duration: u32,
    /// Unilateral VTXO exit delay (seconds).
    pub unilateral_exit_delay: u32,
    /// Boarding exit delay (seconds).
    pub boarding_exit_delay: u32,
    /// Server semver.
    pub version: String,
    /// Dust threshold in satoshis.
    pub dust: u64,
    /// Minimum VTXO amount in satoshis.
    pub vtxo_min_amount: u64,
    /// Maximum VTXO amount in satoshis.
    pub vtxo_max_amount: u64,
}

impl From<ServerInfo> for ServerInfoDto {
    fn from(value: ServerInfo) -> Self {
        Self {
            pubkey: value.pubkey,
            forfeit_pubkey: value.forfeit_pubkey,
            network: value.network,
            session_duration: value.session_duration,
            unilateral_exit_delay: value.unilateral_exit_delay,
            boarding_exit_delay: value.boarding_exit_delay,
            version: value.version,
            dust: value.dust,
            vtxo_min_amount: value.vtxo_min_amount,
            vtxo_max_amount: value.vtxo_max_amount,
        }
    }
}
