//! Esplora-based sweep service for reclaiming expired VTXO outputs.
//!
//! Implements [`SweepService`] by querying an Esplora HTTP API to identify
//! VTXO outputs that have passed their CSV timelock and are eligible for
//! sweeping back to the ASP wallet.

use async_trait::async_trait;
use tracing::{debug, info, warn};

use dark_core::confidential_sweep::sweep_input_for_vtxo;
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::{
    ConfidentialOpeningProvider, NoopConfidentialOpeningProvider, SweepResult, SweepService,
};

/// An output identified as sweepable (past its CSV timelock).
#[derive(Debug, Clone)]
pub struct SweepableVtxoOutput {
    /// Transaction ID containing the output.
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount: u64,
    /// CSV delay (in blocks) that has elapsed.
    pub csv_delay: u32,
    /// Current chain height when identified.
    pub identified_at_height: u32,
}

/// Esplora outspend response.
#[derive(Debug, serde::Deserialize)]
struct OutspendResponse {
    spent: bool,
}

/// Esplora block status for a transaction.
#[derive(Debug, serde::Deserialize)]
struct TxStatus {
    confirmed: bool,
    #[serde(default)]
    block_height: Option<u32>,
}

/// Minimal Esplora transaction response.
#[derive(Debug, serde::Deserialize)]
struct EsploraTxResponse {
    #[allow(dead_code)]
    txid: String,
    status: TxStatus,
}

/// Esplora-based sweep service that identifies expired VTXO outputs.
///
/// Queries the Esplora API to:
/// 1. Get the current chain tip height
/// 2. Check transaction confirmation status and block height
/// 3. Determine if outputs have passed their CSV timelock
/// 4. Log sweepable outputs for future transaction building
///
/// # Note
/// Full sweep transaction building requires `TxBuilder` wiring which is
/// deferred to a follow-up. This implementation identifies and logs
/// sweepable outputs but does not yet build or broadcast sweep transactions.
pub struct EsploraSweepService {
    base_url: String,
    client: reqwest::Client,
    /// Optional VTXO repository for querying expired VTXOs.
    vtxo_repo: Option<Arc<dyn dark_core::ports::VtxoRepository>>,
    /// Optional wallet service for broadcasting sweep transactions.
    wallet: Option<Arc<dyn dark_core::ports::WalletService>>,
    /// Optional tx builder for constructing sweep transactions.
    tx_builder: Option<Arc<dyn dark_core::ports::TxBuilder>>,
    /// Optional round repository for looking up connector trees.
    round_repo: Option<Arc<dyn dark_core::ports::RoundRepository>>,
    /// Provider for confidential VTXO openings (#549). Defaults to a no-op
    /// provider that skips confidential VTXOs.
    opening_provider: Arc<dyn ConfidentialOpeningProvider>,
}

use std::sync::Arc;

impl EsploraSweepService {
    /// Create a new Esplora-based sweep service.
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            vtxo_repo: None,
            wallet: None,
            tx_builder: None,
            round_repo: None,
            opening_provider: Arc::new(NoopConfidentialOpeningProvider),
        }
    }

    /// Plug in a confidential opening provider (#549). Without this, the
    /// service falls back to the no-op provider and skips confidential VTXOs.
    pub fn with_opening_provider(mut self, provider: Arc<dyn ConfidentialOpeningProvider>) -> Self {
        self.opening_provider = provider;
        self
    }

    /// Wire in the dependencies needed for actual sweep transaction building.
    pub fn with_deps(
        mut self,
        vtxo_repo: Arc<dyn dark_core::ports::VtxoRepository>,
        wallet: Arc<dyn dark_core::ports::WalletService>,
        tx_builder: Arc<dyn dark_core::ports::TxBuilder>,
    ) -> Self {
        self.vtxo_repo = Some(vtxo_repo);
        self.wallet = Some(wallet);
        self.tx_builder = Some(tx_builder);
        self
    }

    /// Wire in a round repository for connector sweep support.
    pub fn with_round_repo(
        mut self,
        round_repo: Arc<dyn dark_core::ports::RoundRepository>,
    ) -> Self {
        self.round_repo = Some(round_repo);
        self
    }

    /// Get the current chain tip height from Esplora.
    async fn tip_height(&self) -> ArkResult<u32> {
        let url = format!("{}/blocks/tip/height", self.base_url);
        let resp =
            self.client.get(&url).send().await.map_err(|e| {
                ArkError::Internal(format!("Esplora tip height request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Esplora GET {} returned {}",
                url,
                resp.status()
            )));
        }

        let text = resp
            .text()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to read tip height: {e}")))?;

        text.trim()
            .parse()
            .map_err(|e| ArkError::Internal(format!("Failed to parse tip height '{}': {e}", text)))
    }

    /// Check if a specific output is unspent on-chain.
    async fn is_output_unspent(&self, txid: &str, vout: u32) -> ArkResult<bool> {
        let url = format!("{}/tx/{}/outspend/{}", self.base_url, txid, vout);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("Esplora outspend request failed: {e}")))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(true); // tx not found means output is unspent
        }

        if !resp.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Esplora GET {} returned {}",
                url,
                resp.status()
            )));
        }

        let outspend: OutspendResponse = resp
            .json()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to parse outspend: {e}")))?;

        Ok(!outspend.spent)
    }

    /// Get the confirmation block height of a transaction.
    async fn get_tx_block_height(&self, txid: &str) -> ArkResult<Option<u32>> {
        let url = format!("{}/tx/{}", self.base_url, txid);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("Esplora tx request failed: {e}")))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !resp.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Esplora GET {} returned {}",
                url,
                resp.status()
            )));
        }

        let tx: EsploraTxResponse = resp
            .json()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to parse tx response: {e}")))?;

        if tx.status.confirmed {
            Ok(tx.status.block_height)
        } else {
            Ok(None)
        }
    }

    /// Check if a VTXO output has passed its CSV timelock and is sweepable.
    ///
    /// Returns `Some(SweepableVtxoOutput)` if the output is:
    /// 1. Confirmed on-chain
    /// 2. Unspent
    /// 3. Past its CSV delay relative to confirmation height
    pub async fn check_sweepable(
        &self,
        txid: &str,
        vout: u32,
        amount: u64,
        csv_delay: u32,
    ) -> ArkResult<Option<SweepableVtxoOutput>> {
        // Check if the output is still unspent
        if !self.is_output_unspent(txid, vout).await? {
            debug!(txid = %txid, vout, "Output already spent, not sweepable");
            return Ok(None);
        }

        // Get the confirmation height of the transaction
        let confirm_height = match self.get_tx_block_height(txid).await? {
            Some(h) => h,
            None => {
                debug!(txid = %txid, "Transaction not confirmed, not sweepable");
                return Ok(None);
            }
        };

        // Get current tip to check if CSV has elapsed
        let current_height = self.tip_height().await?;
        let blocks_since_confirm = current_height.saturating_sub(confirm_height);

        if blocks_since_confirm < csv_delay {
            debug!(
                txid = %txid,
                vout,
                blocks_since_confirm,
                csv_delay,
                "CSV timelock not yet elapsed"
            );
            return Ok(None);
        }

        info!(
            txid = %txid,
            vout,
            amount,
            csv_delay,
            blocks_since_confirm,
            "Found sweepable VTXO output"
        );

        Ok(Some(SweepableVtxoOutput {
            txid: txid.to_string(),
            vout,
            amount,
            csv_delay,
            identified_at_height: current_height,
        }))
    }
}

#[async_trait]
impl SweepService for EsploraSweepService {
    async fn sweep_expired_vtxos(&self, current_height: u32) -> ArkResult<SweepResult> {
        info!(
            current_height,
            "EsploraSweepService: checking for expired VTXOs to sweep"
        );

        let (vtxo_repo, wallet, tx_builder) = match (
            &self.vtxo_repo,
            &self.wallet,
            &self.tx_builder,
        ) {
            (Some(r), Some(w), Some(t)) => (r, w, t),
            _ => {
                warn!("EsploraSweepService: missing deps (vtxo_repo/wallet/tx_builder) — skipping sweep");
                return Ok(SweepResult::default());
            }
        };

        // Find expired VTXOs using the efficient DB query (filters by timestamp + swept/spent)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let expired = vtxo_repo.find_expired_vtxos(now).await.unwrap_or_default();

        if expired.is_empty() {
            debug!("EsploraSweepService: no expired VTXOs to sweep");
            return Ok(SweepResult::default());
        }

        info!(
            count = expired.len(),
            "EsploraSweepService: found expired VTXOs"
        );

        // Build sweep inputs, dispatching on confidential vs transparent (#549).
        // Confidential VTXOs without an opening are dropped from this batch.
        let mut sweep_inputs: Vec<dark_core::ports::SweepInput> = Vec::with_capacity(expired.len());
        let mut included = Vec::with_capacity(expired.len());
        for v in &expired {
            let input = if v.is_confidential() {
                let opening = match self.opening_provider.opening_for(v).await {
                    Ok(Some(o)) => o,
                    Ok(None) => {
                        warn!(
                            vtxo_id = %v.outpoint,
                            "EsploraSweepService: confidential VTXO has no opening; skipping"
                        );
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            vtxo_id = %v.outpoint,
                            error = %e,
                            "EsploraSweepService: confidential opening lookup failed; skipping"
                        );
                        continue;
                    }
                };
                match sweep_input_for_vtxo(v, Some(&opening)) {
                    Ok(i) => i,
                    Err(e) => {
                        warn!(
                            vtxo_id = %v.outpoint,
                            error = %e,
                            "EsploraSweepService: failed to build confidential sweep input; skipping"
                        );
                        continue;
                    }
                }
            } else {
                // Transparent path — preserved verbatim.
                dark_core::ports::SweepInput {
                    txid: v.outpoint.txid.clone(),
                    vout: v.outpoint.vout,
                    amount: v.amount,
                    tapscripts: vec![],
                    pubkey: v.pubkey.clone(),
                }
            };
            sweep_inputs.push(input);
            included.push(v.clone());
        }

        if sweep_inputs.is_empty() {
            debug!("EsploraSweepService: no inputs after opening resolution; skipping");
            return Ok(SweepResult::default());
        }

        // Build sweep tx
        let (sweep_tx_hex, sweep_txid) = match tx_builder.build_sweep_tx(&sweep_inputs).await {
            Ok(result) => result,
            Err(e) => {
                warn!(error = %e, "EsploraSweepService: failed to build sweep tx");
                return Ok(SweepResult::default());
            }
        };

        // Broadcast
        match wallet.broadcast_transaction(vec![sweep_tx_hex]).await {
            Ok(txid) => {
                let sats: u64 = sweep_inputs.iter().map(|i| i.amount).sum();
                info!(txid = %txid, vtxos = included.len(), sats, "EsploraSweepService: sweep tx broadcast");
                // Mark VTXOs as swept in the repository
                if let Err(e) = vtxo_repo.mark_vtxos_swept(&included).await {
                    warn!(
                        error = %e,
                        txid = %txid,
                        "EsploraSweepService: failed to mark VTXOs as swept after broadcast"
                    );
                }
                Ok(SweepResult {
                    vtxos_swept: included.len(),
                    sats_recovered: sats,
                    tx_ids: vec![sweep_txid],
                })
            }
            Err(e) => {
                warn!(error = %e, "EsploraSweepService: broadcast failed");
                Ok(SweepResult::default())
            }
        }
    }

    async fn sweep_connectors(&self, round_id: &str) -> ArkResult<SweepResult> {
        info!(
            round_id = %round_id,
            "EsploraSweepService: checking connectors for sweep"
        );

        let (wallet, tx_builder, round_repo) = match (
            &self.wallet,
            &self.tx_builder,
            &self.round_repo,
        ) {
            (Some(w), Some(t), Some(r)) => (w, t, r),
            _ => {
                warn!(
                    round_id = %round_id,
                    "EsploraSweepService: missing deps (wallet/tx_builder/round_repo) — skipping connector sweep"
                );
                return Ok(SweepResult::default());
            }
        };

        // Load the round from the repository to get its connector tree
        let round = match round_repo.get_round_with_id(round_id).await? {
            Some(r) => r,
            None => {
                debug!(
                    round_id = %round_id,
                    "Round not found in repository — skipping connector sweep"
                );
                return Ok(SweepResult::default());
            }
        };

        if round.connectors.is_empty() {
            debug!(round_id = %round_id, "No connectors in round");
            return Ok(SweepResult::default());
        }

        // Get sweepable outputs from the connector tree via TxBuilder
        let sweepable = match tx_builder
            .get_sweepable_batch_outputs(&round.connectors)
            .await?
        {
            Some(s) => s,
            None => {
                debug!(
                    round_id = %round_id,
                    "No sweepable connector outputs found"
                );
                return Ok(SweepResult::default());
            }
        };

        // Check if the connector tx is confirmed and get its block height
        let confirm_height = match self.get_tx_block_height(&sweepable.txid).await? {
            Some(h) => h,
            None => {
                debug!(
                    round_id = %round_id,
                    txid = %sweepable.txid,
                    "Connector tx not confirmed — skipping sweep"
                );
                return Ok(SweepResult::default());
            }
        };

        let current_height = self.tip_height().await?;

        // Verify the CSV timelock has elapsed
        let blocks_since_confirm = current_height.saturating_sub(confirm_height);
        if blocks_since_confirm < sweepable.csv_delay {
            debug!(
                round_id = %round_id,
                blocks_since_confirm,
                csv_delay = sweepable.csv_delay,
                "Connector CSV timelock not yet elapsed"
            );
            return Ok(SweepResult::default());
        }

        // Verify the output is still unspent on-chain
        if !self
            .is_output_unspent(&sweepable.txid, sweepable.vout)
            .await?
        {
            debug!(
                round_id = %round_id,
                txid = %sweepable.txid,
                vout = sweepable.vout,
                "Connector output already spent"
            );
            return Ok(SweepResult::default());
        }

        // Build sweep input from the sweepable connector output
        let input = dark_core::ports::SweepInput {
            txid: sweepable.txid.clone(),
            vout: sweepable.vout,
            amount: sweepable.amount,
            tapscripts: sweepable.tapscripts,
            pubkey: String::new(),
        };

        // Build sweep transaction via TxBuilder
        let (sweep_txid, sweep_tx_hex) = match tx_builder.build_sweep_tx(&[input]).await {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    round_id = %round_id,
                    error = %e,
                    "Failed to build connector sweep tx"
                );
                return Ok(SweepResult::default());
            }
        };

        // Broadcast the sweep transaction
        match wallet.broadcast_transaction(vec![sweep_tx_hex]).await {
            Ok(txid) => {
                info!(
                    round_id = %round_id,
                    txid = %txid,
                    sats = sweepable.amount,
                    "Connector sweep tx broadcast"
                );
                Ok(SweepResult {
                    vtxos_swept: 0, // Connectors are ASP-owned, not user VTXOs
                    sats_recovered: sweepable.amount,
                    tx_ids: vec![sweep_txid],
                })
            }
            Err(e) => {
                warn!(
                    round_id = %round_id,
                    error = %e,
                    "Connector sweep broadcast failed"
                );
                Ok(SweepResult::default())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sweep_expired_vtxos_stub_returns_empty() {
        let mut server = mockito::Server::new_async().await;

        let _tip_mock = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("100000")
            .create_async()
            .await;

        let service = EsploraSweepService::new(&server.url());
        let result = service.sweep_expired_vtxos(100000).await.unwrap();

        assert_eq!(result.vtxos_swept, 0);
        assert_eq!(result.sats_recovered, 0);
        assert!(result.tx_ids.is_empty());
    }

    #[tokio::test]
    async fn test_sweep_connectors_stub_returns_empty() {
        let service = EsploraSweepService::new("http://localhost:3000");
        let result = service.sweep_connectors("round-123").await.unwrap();

        assert_eq!(result.vtxos_swept, 0);
        assert_eq!(result.sats_recovered, 0);
        assert!(result.tx_ids.is_empty());
    }

    #[tokio::test]
    async fn test_check_sweepable_output_past_csv() {
        let mut server = mockito::Server::new_async().await;
        let txid = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        // Output is unspent
        let _outspend_mock = server
            .mock("GET", format!("/tx/{}/outspend/0", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":false}"#)
            .create_async()
            .await;

        // Transaction confirmed at height 99_000
        let _tx_mock = server
            .mock("GET", format!("/tx/{}", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"txid":"{}","status":{{"confirmed":true,"block_height":99000}}}}"#,
                txid
            ))
            .create_async()
            .await;

        // Current tip is 100_000 (1000 blocks later)
        let _tip_mock = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("100000")
            .create_async()
            .await;

        let service = EsploraSweepService::new(&server.url());
        let result = service.check_sweepable(txid, 0, 50_000, 144).await.unwrap();

        assert!(
            result.is_some(),
            "Output should be sweepable (1000 > 144 CSV)"
        );
        let output = result.unwrap();
        assert_eq!(output.txid, txid);
        assert_eq!(output.amount, 50_000);
        assert_eq!(output.csv_delay, 144);
    }

    #[tokio::test]
    async fn test_check_sweepable_csv_not_elapsed() {
        let mut server = mockito::Server::new_async().await;
        let txid = "1122334455667788112233445566778811223344556677881122334455667788";

        let _outspend_mock = server
            .mock("GET", format!("/tx/{}/outspend/0", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":false}"#)
            .create_async()
            .await;

        // Confirmed at 99_900
        let _tx_mock = server
            .mock("GET", format!("/tx/{}", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"txid":"{}","status":{{"confirmed":true,"block_height":99900}}}}"#,
                txid
            ))
            .create_async()
            .await;

        // Tip at 100_000 → only 100 blocks elapsed, CSV=144
        let _tip_mock = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("100000")
            .create_async()
            .await;

        let service = EsploraSweepService::new(&server.url());
        let result = service.check_sweepable(txid, 0, 50_000, 144).await.unwrap();

        assert!(
            result.is_none(),
            "CSV not elapsed — should not be sweepable"
        );
    }

    #[tokio::test]
    async fn test_check_sweepable_already_spent() {
        let mut server = mockito::Server::new_async().await;
        let txid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        let _outspend_mock = server
            .mock("GET", format!("/tx/{}/outspend/0", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":true,"txid":"spending_tx"}"#)
            .create_async()
            .await;

        let service = EsploraSweepService::new(&server.url());
        let result = service.check_sweepable(txid, 0, 50_000, 144).await.unwrap();

        assert!(result.is_none(), "Already spent — not sweepable");
    }

    // ── Confidential VTXO sweep tests (#549) ────────────────────────

    use async_trait::async_trait as test_async_trait;
    use dark_core::confidential_sweep::ConfidentialOpening;
    use dark_core::domain::vtxo::{ConfidentialPayload, Vtxo, VtxoOutpoint};
    use dark_core::domain::{FlatTxTree, Intent};
    use dark_core::ports::{
        BlockTimestamp, BoardingInput, CommitmentTxResult, ConfidentialOpeningProvider,
        SignedBoardingInput, SweepInput, SweepableOutput, TxBuilder, TxInput, ValidForfeitTx,
        VtxoRepository, WalletService, WalletStatus,
    };
    use std::sync::Mutex;

    struct MockRepo {
        expired: Vec<Vtxo>,
        marked: Mutex<Vec<Vtxo>>,
    }

    #[test_async_trait]
    impl VtxoRepository for MockRepo {
        async fn add_vtxos(&self, _vtxos: &[Vtxo]) -> dark_core::error::ArkResult<()> {
            Ok(())
        }
        async fn get_vtxos(
            &self,
            _outpoints: &[VtxoOutpoint],
        ) -> dark_core::error::ArkResult<Vec<Vtxo>> {
            Ok(vec![])
        }
        async fn get_all_vtxos_for_pubkey(
            &self,
            _pubkey: &str,
        ) -> dark_core::error::ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
            Ok((vec![], vec![]))
        }
        async fn spend_vtxos(
            &self,
            _spent: &[(VtxoOutpoint, String)],
            _ark_txid: &str,
        ) -> dark_core::error::ArkResult<()> {
            Ok(())
        }
        async fn find_expired_vtxos(
            &self,
            _before_timestamp: i64,
        ) -> dark_core::error::ArkResult<Vec<Vtxo>> {
            Ok(self.expired.clone())
        }
        async fn mark_vtxos_swept(&self, vtxos: &[Vtxo]) -> dark_core::error::ArkResult<()> {
            self.marked.lock().unwrap().extend_from_slice(vtxos);
            Ok(())
        }
    }

    struct MockTxBuilder {
        captured: Mutex<Vec<Vec<SweepInput>>>,
    }

    #[test_async_trait]
    impl TxBuilder for MockTxBuilder {
        async fn build_commitment_tx(
            &self,
            _signer_pubkey: &bitcoin::XOnlyPublicKey,
            _intents: &[Intent],
            _boarding_inputs: &[BoardingInput],
        ) -> dark_core::error::ArkResult<CommitmentTxResult> {
            Ok(CommitmentTxResult {
                commitment_tx: String::new(),
                vtxo_tree: Vec::new(),
                connector_address: String::new(),
                connectors: Vec::new(),
            })
        }
        async fn verify_forfeit_txs(
            &self,
            _vtxos: &[Vtxo],
            _connectors: &FlatTxTree,
            _txs: &[String],
        ) -> dark_core::error::ArkResult<Vec<ValidForfeitTx>> {
            Ok(Vec::new())
        }
        async fn build_sweep_tx(
            &self,
            inputs: &[SweepInput],
        ) -> dark_core::error::ArkResult<(String, String)> {
            self.captured.lock().unwrap().push(inputs.to_vec());
            Ok((
                "scanner_sweep_txid".to_string(),
                "scanner_sweep_psbt".to_string(),
            ))
        }
        async fn get_sweepable_batch_outputs(
            &self,
            _vtxo_tree: &FlatTxTree,
        ) -> dark_core::error::ArkResult<Option<SweepableOutput>> {
            Ok(None)
        }
        async fn finalize_and_extract(&self, tx: &str) -> dark_core::error::ArkResult<String> {
            Ok(format!("final_{tx}"))
        }
        async fn verify_vtxo_tapscript_sigs(
            &self,
            _tx: &str,
            _must_include_signer: bool,
        ) -> dark_core::error::ArkResult<bool> {
            Ok(true)
        }
        async fn verify_boarding_tapscript_sigs(
            &self,
            _signed_tx: &str,
            _commitment_tx: &str,
        ) -> dark_core::error::ArkResult<std::collections::HashMap<u32, SignedBoardingInput>>
        {
            Ok(std::collections::HashMap::new())
        }
    }

    struct MockWallet;

    #[test_async_trait]
    impl WalletService for MockWallet {
        async fn status(&self) -> dark_core::error::ArkResult<WalletStatus> {
            Ok(WalletStatus {
                initialized: true,
                unlocked: true,
                synced: true,
            })
        }
        async fn get_forfeit_pubkey(&self) -> dark_core::error::ArkResult<bitcoin::XOnlyPublicKey> {
            Ok(bitcoin::XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap())
        }
        async fn derive_connector_address(&self) -> dark_core::error::ArkResult<String> {
            Ok("addr".into())
        }
        async fn sign_transaction(
            &self,
            tx: &str,
            _extract_raw: bool,
        ) -> dark_core::error::ArkResult<String> {
            Ok(tx.to_string())
        }
        async fn select_utxos(
            &self,
            _amount: u64,
            _confirmed_only: bool,
        ) -> dark_core::error::ArkResult<(Vec<TxInput>, u64)> {
            Ok((vec![], 0))
        }
        async fn broadcast_transaction(
            &self,
            _txs: Vec<String>,
        ) -> dark_core::error::ArkResult<String> {
            Ok("scanner_broadcast_txid".into())
        }
        async fn fee_rate(&self) -> dark_core::error::ArkResult<u64> {
            Ok(10)
        }
        async fn get_current_block_time(&self) -> dark_core::error::ArkResult<BlockTimestamp> {
            Ok(BlockTimestamp {
                height: 200,
                timestamp: 1_700_000_000,
            })
        }
        async fn get_dust_amount(&self) -> dark_core::error::ArkResult<u64> {
            Ok(546)
        }
        async fn get_outpoint_status(
            &self,
            _outpoint: &VtxoOutpoint,
        ) -> dark_core::error::ArkResult<bool> {
            Ok(false)
        }
    }

    struct FixedOpeningProvider(ConfidentialOpening);
    #[test_async_trait]
    impl ConfidentialOpeningProvider for FixedOpeningProvider {
        async fn opening_for(
            &self,
            _vtxo: &Vtxo,
        ) -> dark_core::error::ArkResult<Option<ConfidentialOpening>> {
            Ok(Some(self.0.clone()))
        }
    }

    fn make_payload(seed: u8) -> ConfidentialPayload {
        let mut commitment = [0u8; 33];
        commitment[0] = 0x02;
        commitment[1] = seed.max(1);
        ConfidentialPayload::new(commitment, vec![0xab; 8], [seed; 32], {
            let mut e = [0u8; 33];
            e[0] = 0x03;
            e[1] = seed;
            e
        })
    }

    fn make_conf(seed: u8) -> Vtxo {
        let mut v = Vtxo::new_confidential(
            VtxoOutpoint::new(format!("conf_{seed}"), u32::from(seed)),
            "deadbeef".to_string(),
            make_payload(seed),
        );
        v.expires_at = 1;
        v
    }

    fn make_plain(seed: u8, amount: u64) -> Vtxo {
        let mut v = Vtxo::new(
            VtxoOutpoint::new(format!("plain_{seed}"), u32::from(seed)),
            amount,
            "feedbeef".to_string(),
        );
        v.expires_at = 1;
        v
    }

    /// Issue #549: confidential VTXO past CSV → sweep tx is constructed and
    /// witness opens the commitment correctly via the EsploraSweepService.
    #[tokio::test]
    async fn test_esplora_confidential_sweep_attaches_witness_script() {
        let vtxo = make_conf(7);
        let payload = vtxo.confidential.clone().unwrap();
        let opening = ConfidentialOpening::new(50_000, [0xcd; 32]);

        let repo = Arc::new(MockRepo {
            expired: vec![vtxo],
            marked: Mutex::new(Vec::new()),
        });
        let tx_builder = Arc::new(MockTxBuilder {
            captured: Mutex::new(Vec::new()),
        });

        let svc = EsploraSweepService::new("http://localhost:1")
            .with_deps(repo.clone(), Arc::new(MockWallet), tx_builder.clone())
            .with_opening_provider(Arc::new(FixedOpeningProvider(opening)));

        let result = svc.sweep_expired_vtxos(200).await.unwrap();
        assert_eq!(result.vtxos_swept, 1);
        assert_eq!(result.sats_recovered, 50_000);

        // Witness script encodes the commitment opening
        let captured = tx_builder.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let inputs = &captured[0];
        assert_eq!(inputs.len(), 1);
        assert!(
            !inputs[0].tapscripts.is_empty(),
            "confidential exit script attached"
        );
        let script = &inputs[0].tapscripts[0];
        assert!(script.contains(&hex::encode(payload.amount_commitment)));
        assert!(script.contains(&hex::encode(50_000u64.to_be_bytes())));
        assert!(script.contains(&hex::encode([0xcd; 32])));

        // Repo marked it
        assert_eq!(repo.marked.lock().unwrap().len(), 1);
    }

    /// Issue #549 negative: confidential VTXO with no opening is left
    /// unswept (no broadcast, no DB mark).
    #[tokio::test]
    async fn test_esplora_confidential_sweep_skips_without_opening() {
        let vtxo = make_conf(3);
        let repo = Arc::new(MockRepo {
            expired: vec![vtxo],
            marked: Mutex::new(Vec::new()),
        });
        let tx_builder = Arc::new(MockTxBuilder {
            captured: Mutex::new(Vec::new()),
        });

        // No opening_provider — falls back to NoopConfidentialOpeningProvider
        let svc = EsploraSweepService::new("http://localhost:1").with_deps(
            repo.clone(),
            Arc::new(MockWallet),
            tx_builder.clone(),
        );

        let result = svc.sweep_expired_vtxos(200).await.unwrap();
        assert_eq!(result.vtxos_swept, 0);
        assert!(result.tx_ids.is_empty());
        assert!(
            tx_builder.captured.lock().unwrap().is_empty(),
            "no sweep tx built when opening is missing"
        );
        assert!(
            repo.marked.lock().unwrap().is_empty(),
            "VTXO not marked swept"
        );
    }

    /// Issue #549: mixed-round (transparent + confidential) sweeps cleanly.
    #[tokio::test]
    async fn test_esplora_mixed_round_sweep() {
        let conf = make_conf(1);
        let plain = make_plain(2, 30_000);

        let repo = Arc::new(MockRepo {
            expired: vec![conf, plain],
            marked: Mutex::new(Vec::new()),
        });
        let tx_builder = Arc::new(MockTxBuilder {
            captured: Mutex::new(Vec::new()),
        });

        let svc = EsploraSweepService::new("http://localhost:1")
            .with_deps(repo.clone(), Arc::new(MockWallet), tx_builder.clone())
            .with_opening_provider(Arc::new(FixedOpeningProvider(ConfidentialOpening::new(
                15_000, [0xaa; 32],
            ))));

        let result = svc.sweep_expired_vtxos(200).await.unwrap();
        assert_eq!(result.vtxos_swept, 2);
        assert_eq!(result.sats_recovered, 45_000);

        let captured = tx_builder.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].len(), 2);
    }

    /// Regression: the legacy transparent-only path produces an identical
    /// SweepInput shape (empty tapscripts, plaintext amount) as before #549.
    #[tokio::test]
    async fn test_esplora_transparent_sweep_unchanged_regression() {
        let vtxo = make_plain(9, 50_000);

        let repo = Arc::new(MockRepo {
            expired: vec![vtxo.clone()],
            marked: Mutex::new(Vec::new()),
        });
        let tx_builder = Arc::new(MockTxBuilder {
            captured: Mutex::new(Vec::new()),
        });

        // Default no-op opening provider — transparent must work unchanged.
        let svc = EsploraSweepService::new("http://localhost:1").with_deps(
            repo.clone(),
            Arc::new(MockWallet),
            tx_builder.clone(),
        );

        let result = svc.sweep_expired_vtxos(200).await.unwrap();
        assert_eq!(result.vtxos_swept, 1);
        assert_eq!(result.sats_recovered, 50_000);

        let captured = tx_builder.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let inputs = &captured[0];
        assert_eq!(inputs.len(), 1);
        assert!(
            inputs[0].tapscripts.is_empty(),
            "transparent path must keep tapscripts empty (regression invariant)"
        );
        assert_eq!(inputs[0].amount, 50_000);
        assert_eq!(inputs[0].txid, vtxo.outpoint.txid);
        assert_eq!(inputs[0].vout, vtxo.outpoint.vout);
        assert_eq!(inputs[0].pubkey, vtxo.pubkey);

        assert_eq!(repo.marked.lock().unwrap().len(), 1);
    }
}
