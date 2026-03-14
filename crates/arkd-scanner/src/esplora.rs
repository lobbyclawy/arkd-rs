//! Esplora-based blockchain scanner.
//!
//! Polls an Esplora HTTP API to detect on-chain spends of watched scripts.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, warn};

use arkd_core::error::ArkResult;
use arkd_core::ports::{BlockchainScanner, ScriptSpentEvent};

/// Esplora transaction response (minimal fields we care about).
#[derive(Debug, Deserialize)]
struct EsploraTx {
    txid: String,
    status: EsploraTxStatus,
    vin: Vec<EsploraVin>,
}

#[derive(Debug, Deserialize)]
struct EsploraTxStatus {
    confirmed: bool,
    block_height: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct EsploraVin {
    prevout: Option<EsploraPrevout>,
}

#[derive(Debug, Deserialize)]
struct EsploraPrevout {
    scriptpubkey: String,
}

/// Blockchain scanner that polls an Esplora HTTP API.
///
/// Watches script pubkeys and emits [`ScriptSpentEvent`]s when a watched
/// script is spent in a confirmed transaction.
pub struct EsploraScanner {
    base_url: String,
    client: reqwest::Client,
    /// Watched script pubkeys stored as hex strings.
    watched: RwLock<HashSet<String>>,
    /// Track txids we've already notified about per script (hex) to avoid duplicates.
    seen_txids: RwLock<HashMap<String, HashSet<String>>>,
    sender: broadcast::Sender<ScriptSpentEvent>,
    poll_interval: Duration,
}

impl EsploraScanner {
    /// Create a new Esplora scanner.
    ///
    /// # Arguments
    /// * `base_url` — Esplora API base URL (e.g. `https://blockstream.info/testnet/api`)
    /// * `poll_interval_secs` — How often to poll for new transactions
    pub fn new(base_url: &str, poll_interval_secs: u64) -> Self {
        let (sender, _) = broadcast::channel(256);
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            watched: RwLock::new(HashSet::new()),
            seen_txids: RwLock::new(HashMap::new()),
            sender,
            poll_interval: Duration::from_secs(poll_interval_secs),
        }
    }

    /// Start the background polling loop. Call once at startup.
    ///
    /// Spawns a tokio task that periodically checks all watched scripts
    /// for on-chain spends.
    pub fn start_polling(self: Arc<Self>) {
        tokio::spawn(async move {
            debug!("EsploraScanner: polling loop started");
            loop {
                self.poll_once().await;
                tokio::time::sleep(self.poll_interval).await;
            }
        });
    }

    /// Run a single polling cycle across all watched scripts.
    async fn poll_once(&self) {
        let scripts: Vec<String> = {
            let watched = self.watched.read().await;
            watched.iter().cloned().collect()
        };

        for script_hex in scripts {
            if let Err(e) = self.check_script(&script_hex).await {
                warn!(
                    script = %script_hex,
                    error = %e,
                    "EsploraScanner: failed to check script"
                );
            }
        }
    }

    /// Check a single script for new spending transactions.
    async fn check_script(
        &self,
        script_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Esplora uses the script hash (SHA256 of the scriptpubkey bytes, reversed)
        let script_bytes = hex::decode(script_hex)?;
        let script_hash = {
            use bitcoin::hashes::{sha256, Hash};
            let hash = sha256::Hash::hash(&script_bytes);
            let mut bytes = hash.to_byte_array();
            bytes.reverse();
            hex::encode(bytes)
        };

        let url = format!("{}/scripthash/{}/txs", self.base_url, script_hash);
        let resp = self.client.get(&url).send().await?;

        if !resp.status().is_success() {
            warn!(
                url = %url,
                status = %resp.status(),
                "EsploraScanner: non-success response"
            );
            return Ok(());
        }

        let txs: Vec<EsploraTx> = resp.json().await?;

        for tx in txs {
            // Only care about confirmed transactions
            if !tx.status.confirmed {
                continue;
            }

            let block_height = tx.status.block_height.unwrap_or(0);

            // Check if any input spends our watched script
            let spends_watched = tx.vin.iter().any(|vin| {
                vin.prevout
                    .as_ref()
                    .map(|p| p.scriptpubkey == *script_hex)
                    .unwrap_or(false)
            });

            if !spends_watched {
                continue;
            }

            // Check if we've already notified about this txid for this script
            let already_seen = {
                let seen = self.seen_txids.read().await;
                seen.get(script_hex)
                    .map(|s| s.contains(&tx.txid))
                    .unwrap_or(false)
            };

            if already_seen {
                continue;
            }

            // Mark as seen
            {
                let mut seen = self.seen_txids.write().await;
                seen.entry(script_hex.to_string())
                    .or_default()
                    .insert(tx.txid.clone());
            }

            let event = ScriptSpentEvent {
                script_pubkey: script_bytes.clone(),
                spending_txid: tx.txid.clone(),
                block_height,
            };

            debug!(
                txid = %tx.txid,
                height = block_height,
                "EsploraScanner: script spent on-chain"
            );

            if self.sender.send(event).is_err() {
                // No active receivers — that's fine
            }
        }

        Ok(())
    }
}

#[async_trait]
impl BlockchainScanner for EsploraScanner {
    async fn watch_script(&self, script_pubkey: Vec<u8>) -> ArkResult<()> {
        let hex_key = hex::encode(&script_pubkey);
        self.watched.write().await.insert(hex_key);
        Ok(())
    }

    async fn unwatch_script(&self, script_pubkey: &[u8]) -> ArkResult<()> {
        let hex_key = hex::encode(script_pubkey);
        self.watched.write().await.remove(&hex_key);
        // Also clean up seen txids for this script
        self.seen_txids.write().await.remove(&hex_key);
        Ok(())
    }

    fn notification_channel(&self) -> broadcast::Receiver<ScriptSpentEvent> {
        self.sender.subscribe()
    }

    async fn tip_height(&self) -> ArkResult<u32> {
        let url = format!("{}/blocks/tip/height", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| arkd_core::error::ArkError::Internal(e.to_string()))?;

        let text = resp
            .text()
            .await
            .map_err(|e| arkd_core::error::ArkError::Internal(e.to_string()))?;

        let height: u32 = text.trim().parse().map_err(|e: std::num::ParseIntError| {
            arkd_core::error::ArkError::Internal(format!(
                "failed to parse tip height '{}': {}",
                text.trim(),
                e
            ))
        })?;

        Ok(height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esplora_scanner_construction() {
        let scanner = EsploraScanner::new("https://blockstream.info/testnet/api", 30);
        assert_eq!(scanner.base_url, "https://blockstream.info/testnet/api");
        assert_eq!(scanner.poll_interval, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_esplora_scanner_watch_unwatch() {
        let scanner = EsploraScanner::new("http://localhost:3000", 10);
        let script = vec![0x00, 0x14, 0xab, 0xcd];

        assert!(scanner.watch_script(script.clone()).await.is_ok());
        {
            let watched = scanner.watched.read().await;
            assert!(watched.contains(&hex::encode(&script)));
        }

        assert!(scanner.unwatch_script(&script).await.is_ok());
        {
            let watched = scanner.watched.read().await;
            assert!(!watched.contains(&hex::encode(&script)));
        }
    }

    #[tokio::test]
    async fn test_esplora_scanner_as_trait_object() {
        let scanner: Arc<dyn BlockchainScanner> =
            Arc::new(EsploraScanner::new("http://localhost:3000", 10));
        assert!(scanner.watch_script(vec![0x01]).await.is_ok());
        let _rx = scanner.notification_channel();
    }
}
