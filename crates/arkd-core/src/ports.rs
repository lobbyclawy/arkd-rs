//! Ports - External interfaces for dependency inversion
//!
//! Following hexagonal architecture, these traits define
//! the contracts that external adapters must implement.

use async_trait::async_trait;

/// Wallet service interface for Bitcoin operations
#[async_trait]
pub trait WalletService: Send + Sync {
    // TODO (Issue #4): Add wallet methods
    // - async fn get_balance(&self) -> Result<u64>;
    // - async fn get_new_address(&self) -> Result<Address>;
    // - async fn sign_transaction(&self, psbt: &mut Psbt) -> Result<()>;
    // - async fn broadcast_transaction(&self, tx: Transaction) -> Result<Txid>;
}

/// Database service interface for persistence
#[async_trait]
pub trait DatabaseService: Send + Sync {
    // TODO (Issue #5): Add database methods
    // - async fn get_round(&self, id: &str) -> Result<Round>;
    // - async fn save_vtxo(&self, vtxo: &VTXO) -> Result<()>;
    // - async fn list_exits(&self, status: ExitStatus) -> Result<Vec<Exit>>;
}

/// API service interface for external communication
#[async_trait]
pub trait ApiService: Send + Sync {
    // TODO (Issue #9): Add API methods
    // - async fn handle_register(&self, req: RegisterRequest) -> Result<RegisterResponse>;
    // - async fn handle_exit(&self, req: ExitRequest) -> Result<ExitResponse>;
    // - async fn get_round_status(&self, id: &str) -> Result<RoundStatus>;
}
