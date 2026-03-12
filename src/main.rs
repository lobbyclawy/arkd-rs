use anyhow::Result;
use tracing::{info, Level};

use arkd_api::ServerConfig;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    info!("Starting arkd-rs - Ark protocol server (Rust)");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // API server configuration
    let api_config = ServerConfig::default();
    info!(
        grpc_addr = %api_config.grpc_addr,
        admin_addr = %api_config.admin_addr(),
        "API endpoints configured"
    );

    // TODO: Initialize core service with real dependencies
    // For now, the server starts but the core service needs to be wired up
    // with wallet, signer, vtxo_repo, tx_builder, cache, and events.

    info!("Server initialization complete");
    info!(
        "gRPC listening on {} (user API) and {} (admin API)",
        api_config.grpc_addr,
        api_config.admin_addr()
    );

    // Keep server running
    tokio::signal::ctrl_c().await?;
    info!("Shutting down gracefully...");

    Ok(())
}
