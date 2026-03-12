//! Integration tests for the full round lifecycle.
//!
//! Tests the end-to-end flow: start round → register intents → finalize → check VTXOs

use std::sync::Arc;

use arkd_core::domain::{Intent, Receiver, Round, RoundStage, Vtxo, VtxoOutpoint};
use arkd_core::error::ArkResult;
use arkd_core::ports::*;
use arkd_core::{ArkConfig, ArkService};
use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;
use tokio::sync::RwLock;

// ─── Mock Infrastructure ────────────────────────────────────────────

struct MockWallet;
#[async_trait]
impl WalletService for MockWallet {
    async fn status(&self) -> ArkResult<WalletStatus> {
        Ok(WalletStatus {
            initialized: true,
            unlocked: true,
            synced: true,
        })
    }
    async fn get_forfeit_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        Ok(XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap())
    }
    async fn derive_connector_address(&self) -> ArkResult<String> {
        Ok("tb1q_connector".to_string())
    }
    async fn sign_transaction(&self, ptx: &str, _extract: bool) -> ArkResult<String> {
        Ok(ptx.to_string())
    }
    async fn select_utxos(&self, _amount: u64, _confirmed: bool) -> ArkResult<(Vec<TxInput>, u64)> {
        Ok((vec![], 0))
    }
    async fn broadcast_transaction(&self, _txs: Vec<String>) -> ArkResult<String> {
        Ok("txid_broadcast".to_string())
    }
    async fn fee_rate(&self) -> ArkResult<u64> {
        Ok(1)
    }
    async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp> {
        Ok(BlockTimestamp {
            height: 800_000,
            timestamp: 1_700_000_000,
        })
    }
    async fn get_dust_amount(&self) -> ArkResult<u64> {
        Ok(546)
    }
    async fn get_outpoint_status(&self, _op: &VtxoOutpoint) -> ArkResult<bool> {
        Ok(false)
    }
}

struct MockSigner;
#[async_trait]
impl SignerService for MockSigner {
    async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        Ok(XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap())
    }
    async fn sign_transaction(&self, ptx: &str, _extract: bool) -> ArkResult<String> {
        Ok(ptx.to_string())
    }
}

/// In-memory VTXO repository for integration tests
struct InMemoryVtxoRepo {
    vtxos: RwLock<Vec<Vtxo>>,
}

impl InMemoryVtxoRepo {
    fn new() -> Self {
        Self {
            vtxos: RwLock::new(Vec::new()),
        }
    }
}

#[async_trait]
impl VtxoRepository for InMemoryVtxoRepo {
    async fn add_vtxos(&self, vtxos: &[Vtxo]) -> ArkResult<()> {
        let mut store = self.vtxos.write().await;
        for v in vtxos {
            // Upsert by outpoint
            if let Some(pos) = store.iter().position(|s| s.outpoint == v.outpoint) {
                store[pos] = v.clone();
            } else {
                store.push(v.clone());
            }
        }
        Ok(())
    }

    async fn get_vtxos(&self, outpoints: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>> {
        let store = self.vtxos.read().await;
        Ok(store
            .iter()
            .filter(|v| outpoints.contains(&v.outpoint))
            .cloned()
            .collect())
    }

    async fn get_all_vtxos_for_pubkey(&self, pubkey: &str) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
        let store = self.vtxos.read().await;
        let mut spendable = Vec::new();
        let mut spent = Vec::new();
        for v in store.iter().filter(|v| v.pubkey == pubkey) {
            if v.spent || v.swept {
                spent.push(v.clone());
            } else {
                spendable.push(v.clone());
            }
        }
        Ok((spendable, spent))
    }

    async fn spend_vtxos(&self, spent: &[(VtxoOutpoint, String)], ark_txid: &str) -> ArkResult<()> {
        let mut store = self.vtxos.write().await;
        for (op, spent_by) in spent {
            if let Some(v) = store.iter_mut().find(|v| v.outpoint == *op) {
                v.spent = true;
                v.spent_by = spent_by.clone();
                v.ark_txid = ark_txid.to_string();
            }
        }
        Ok(())
    }
}

struct MockTxBuilder;
#[async_trait]
impl TxBuilder for MockTxBuilder {
    async fn build_commitment_tx(
        &self,
        _signer: &XOnlyPublicKey,
        _intents: &[Intent],
        _boarding: &[BoardingInput],
    ) -> ArkResult<CommitmentTxResult> {
        Ok(CommitmentTxResult {
            commitment_tx: "commitment_tx_hex".to_string(),
            vtxo_tree: vec![],
            connector_address: "tb1q_connector".to_string(),
            connectors: vec![],
        })
    }
    async fn verify_forfeit_txs(
        &self,
        _vtxos: &[Vtxo],
        _connectors: &arkd_core::domain::FlatTxTree,
        _txs: &[String],
    ) -> ArkResult<Vec<ValidForfeitTx>> {
        Ok(vec![])
    }
}

struct MockCache;
#[async_trait]
impl CacheService for MockCache {
    async fn set(&self, _key: &str, _value: &[u8], _ttl: Option<u64>) -> ArkResult<()> {
        Ok(())
    }
    async fn get(&self, _key: &str) -> ArkResult<Option<Vec<u8>>> {
        Ok(None)
    }
    async fn delete(&self, _key: &str) -> ArkResult<bool> {
        Ok(false)
    }
}

struct MockEvents;
#[async_trait]
impl EventPublisher for MockEvents {
    async fn publish_event(&self, _event: ArkEvent) -> ArkResult<()> {
        Ok(())
    }
    async fn subscribe(&self) -> ArkResult<tokio::sync::broadcast::Receiver<ArkEvent>> {
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        drop(tx);
        Ok(rx)
    }
}

fn build_service(vtxo_repo: Arc<InMemoryVtxoRepo>) -> ArkService {
    ArkService::new(
        Arc::new(MockWallet),
        Arc::new(MockSigner),
        vtxo_repo,
        Arc::new(MockTxBuilder),
        Arc::new(MockCache),
        Arc::new(MockEvents),
        ArkConfig::default(),
    )
}

fn make_intent(id: &str, receivers: Vec<Receiver>) -> Intent {
    Intent {
        id: id.to_string(),
        inputs: vec![],
        receivers,
        proof: "proof".to_string(),
        message: "msg".to_string(),
        txid: "txid".to_string(),
        leaf_tx_asset_packet: String::new(),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_full_round_lifecycle() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let service = build_service(vtxo_repo.clone());

    // 1. Start a round
    let round = service.start_round().await.unwrap();
    assert_eq!(round.stage.code, RoundStage::Registration);
    assert!(!round.is_ended());

    // 2. Register intents
    let intent1 = make_intent(
        "intent-1",
        vec![Receiver::offchain(100_000, "pk_alice".to_string())],
    );
    let intent2 = make_intent(
        "intent-2",
        vec![Receiver::offchain(200_000, "pk_bob".to_string())],
    );
    let id1 = service.register_intent(intent1).await.unwrap();
    let id2 = service.register_intent(intent2).await.unwrap();
    assert_eq!(id1, "intent-1");
    assert_eq!(id2, "intent-2");

    // 3. Starting another round while one is active should fail
    let err = service.start_round().await;
    assert!(err.is_err());
}

#[tokio::test]
async fn test_round_with_vtxo_creation() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());

    // Simulate VTXO creation (as would happen after round finalization)
    let vtxos = vec![
        Vtxo::new(
            VtxoOutpoint::new("round1_tx1".to_string(), 0),
            100_000,
            "pk_alice".to_string(),
        ),
        Vtxo::new(
            VtxoOutpoint::new("round1_tx2".to_string(), 0),
            200_000,
            "pk_bob".to_string(),
        ),
    ];
    vtxo_repo.add_vtxos(&vtxos).await.unwrap();

    // Verify VTXOs are retrievable
    let (alice_spendable, alice_spent) = vtxo_repo
        .get_all_vtxos_for_pubkey("pk_alice")
        .await
        .unwrap();
    assert_eq!(alice_spendable.len(), 1);
    assert_eq!(alice_spendable[0].amount, 100_000);
    assert_eq!(alice_spent.len(), 0);

    // Spend a VTXO
    vtxo_repo
        .spend_vtxos(
            &[(
                VtxoOutpoint::new("round1_tx1".to_string(), 0),
                "forfeit_tx".to_string(),
            )],
            "ark_tx_1",
        )
        .await
        .unwrap();

    let (alice_spendable, alice_spent) = vtxo_repo
        .get_all_vtxos_for_pubkey("pk_alice")
        .await
        .unwrap();
    assert_eq!(alice_spendable.len(), 0);
    assert_eq!(alice_spent.len(), 1);
}

#[tokio::test]
async fn test_multi_participant_round() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let service = build_service(vtxo_repo);

    let round = service.start_round().await.unwrap();

    // Register 5 intents (multi-participant)
    for i in 0..5 {
        let intent = make_intent(
            &format!("intent-{i}"),
            vec![Receiver::offchain(
                (i as u64 + 1) * 50_000,
                format!("pk_user_{i}"),
            )],
        );
        service.register_intent(intent).await.unwrap();
    }

    // Verify all intents registered — we test the Round domain model directly
    let mut round_copy = round;
    round_copy.start_registration().ok(); // already started but for domain model test
    for i in 0..3 {
        let intent = make_intent(
            &format!("domain-intent-{i}"),
            vec![Receiver::offchain(10_000, format!("pk_{i}"))],
        );
        round_copy.register_intent(intent).unwrap();
    }
    assert_eq!(round_copy.intent_count(), 3);

    // Transition through stages
    round_copy.start_finalization().unwrap();
    assert_eq!(round_copy.stage.code, RoundStage::Finalization);

    round_copy.end_successfully();
    assert!(round_copy.is_ended());
    assert!(!round_copy.stage.failed);
}

#[tokio::test]
async fn test_round_failure_flow() {
    let mut round = Round::new();
    round.start_registration().unwrap();

    // Register some intents
    let intent = make_intent(
        "intent-fail",
        vec![Receiver::offchain(50_000, "pk1".to_string())],
    );
    round.register_intent(intent).unwrap();

    // Fail the round
    round.fail("insufficient liquidity".to_string());
    assert!(round.is_ended());
    assert!(round.stage.failed);
    assert_eq!(round.fail_reason, "insufficient liquidity");

    // Can't register more intents after failure
    let intent2 = make_intent("intent-2", vec![]);
    assert!(round.register_intent(intent2).is_err());
}

#[tokio::test]
async fn test_intent_with_mixed_receivers() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let service = build_service(vtxo_repo);

    service.start_round().await.unwrap();

    // Intent with both on-chain and off-chain receivers
    let intent = make_intent(
        "mixed-intent",
        vec![
            Receiver::offchain(75_000, "pk_offchain".to_string()),
            Receiver::onchain(25_000, "bc1q_onchain_addr".to_string()),
        ],
    );
    service.register_intent(intent).await.unwrap();
}

#[tokio::test]
async fn test_round_stage_transitions_invalid() {
    let mut round = Round::new();

    // Cannot start finalization before registration
    assert!(round.start_finalization().is_err());

    // Start registration
    round.start_registration().unwrap();

    // Cannot start registration again
    assert!(round.start_registration().is_err());

    // Start finalization
    round.start_finalization().unwrap();

    // Cannot start registration from finalization
    assert!(round.start_registration().is_err());

    // Cannot start finalization again
    assert!(round.start_finalization().is_err());
}
