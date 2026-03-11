//! Error types for Bitcoin operations

use thiserror::Error;

/// Bitcoin-specific errors
#[derive(Error, Debug)]
pub enum BitcoinError {
    /// Transaction building error
    #[error("Transaction build failed: {0}")]
    TransactionBuildError(String),

    /// PSBT error
    #[error("PSBT error: {0}")]
    PsbtError(String),

    /// Script error
    #[error("Script error: {0}")]
    ScriptError(String),

    /// UTXO error
    #[error("UTXO error: {0}")]
    UtxoError(String),

    /// RPC error
    #[error("RPC error: {0}")]
    RpcError(String),

    /// Insufficient funds
    #[error("Insufficient funds: required {required} sats, available {available} sats")]
    InsufficientFunds { required: u64, available: u64 },

    /// Invalid address
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid amount
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for Bitcoin operations
pub type BitcoinResult<T> = Result<T, BitcoinError>;
