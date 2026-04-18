//! Shared server state held in an axum `State` extractor.

use std::sync::Arc;

use dark_api::proto::ark_v1::ark_service_client::ArkServiceClient;
use dark_api::proto::ark_v1::indexer_service_client::IndexerServiceClient;
use dark_client::ArkClient;
use tokio::sync::Mutex;
use tonic::transport::Channel;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    ark: Mutex<ArkClient>,
    ark_raw: Mutex<ArkServiceClient<Channel>>,
    indexer: Mutex<IndexerServiceClient<Channel>>,
    grpc_url: String,
}

impl AppState {
    /// Connect to the upstream dark server and wrap it in shareable state.
    pub async fn connect(config: &Config) -> anyhow::Result<Self> {
        let mut ark = ArkClient::new(config.dark_grpc_url.clone());
        ark.connect()
            .await
            .map_err(|e| anyhow::anyhow!("connect to dark at {}: {e}", config.dark_grpc_url))?;

        let channel = Channel::from_shared(config.dark_grpc_url.clone())
            .map_err(|e| anyhow::anyhow!("invalid grpc url: {e}"))?
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("indexer channel: {e}"))?;
        let indexer = IndexerServiceClient::new(channel.clone());
        let ark_raw = ArkServiceClient::new(channel);

        Ok(Self {
            inner: Arc::new(Inner {
                ark: Mutex::new(ark),
                ark_raw: Mutex::new(ark_raw),
                indexer: Mutex::new(indexer),
                grpc_url: config.dark_grpc_url.clone(),
            }),
        })
    }

    /// Lock the Ark client for a single RPC.
    pub async fn ark(&self) -> tokio::sync::MutexGuard<'_, ArkClient> {
        self.inner.ark.lock().await
    }

    /// Lock the Indexer client for a single RPC.
    pub async fn indexer(&self) -> tokio::sync::MutexGuard<'_, IndexerServiceClient<Channel>> {
        self.inner.indexer.lock().await
    }

    /// Lock the raw ArkService client for RPCs not yet exposed by `dark-client`.
    pub async fn ark_raw(&self) -> tokio::sync::MutexGuard<'_, ArkServiceClient<Channel>> {
        self.inner.ark_raw.lock().await
    }

    /// Upstream gRPC URL. Used by routes that need a fresh raw tonic client
    /// for RPCs not yet exposed by `dark-client`.
    pub fn grpc_url(&self) -> &str {
        &self.inner.grpc_url
    }
}
