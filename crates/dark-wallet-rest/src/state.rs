//! Shared server state held in an axum `State` extractor.

use std::sync::Arc;

use dark_client::ArkClient;
use tokio::sync::Mutex;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    ark: Mutex<ArkClient>,
}

impl AppState {
    /// Connect to the upstream dark server and wrap it in shareable state.
    pub async fn connect(config: &Config) -> anyhow::Result<Self> {
        let mut ark = ArkClient::new(config.dark_grpc_url.clone());
        ark.connect()
            .await
            .map_err(|e| anyhow::anyhow!("connect to dark at {}: {e}", config.dark_grpc_url))?;
        Ok(Self {
            inner: Arc::new(Inner {
                ark: Mutex::new(ark),
            }),
        })
    }

    /// Lock the Ark client for a single RPC.
    pub async fn ark(&self) -> tokio::sync::MutexGuard<'_, ArkClient> {
        self.inner.ark.lock().await
    }
}
