//! Integration tests for collaborative and unilateral exit flows.

use std::sync::Arc;

use arkd_core::domain::{
    CollaborativeExitRequest, Exit, ExitStatus, ExitType, Intent, UnilateralExitRequest, Vtxo,
    VtxoOutpoint,
};
use arkd_core::error::ArkResult;
use arkd_core::ports::*;
use arkd_core::{ArkConfig, ArkService};
use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;
use secp256k1::{rand::rngs::OsRng, Secp256k1};
use std::str::FromStr;
use tokio::sync::RwLock;

// ─── Mock Infrastructure ────────────────────────────────────────────

fn test_xonly_pubkey() -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let (_, pk) = secp.generate_keypair(&mut OsRng);
    XOnlyPublicKey::from(pk)
}

fn test_address() -> bitcoin::Address<bitcoin::address::NetworkUnchecked> {
    bitcoin::Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap()
}

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
    async fn sign_transaction(&self, ptx: &str, _: bool) -> ArkResult<String> {
        Ok(ptx.to_string())
    }
    async fn select_utxos(&self, _: u64, _: bool) -> ArkResult<(Vec<TxInput>, u64)> {
        Ok((vec![], 0))
    }
    async fn broadcast_transaction(&self, _: Vec<String>) -> ArkResult<String> {
        Ok("txid".to_string())
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
    async fn get_outpoint_status(&self, _: &VtxoOutpoint) -> ArkResult<bool> {
        Ok(false)
    }
}

struct MockSigner;
#[async_trait]
impl SignerService for MockSigner {
    async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        Ok(XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap())
    }
    async fn sign_transaction(&self, ptx: &str, _: bool) -> ArkResult<String> {
        Ok(ptx.to_string())
    }
}

struct InMemoryVtxoRepo {
    vtxos: RwLock<Vec<Vtxo>>,
}

impl InMemoryVtxoRepo {
    fn new() -> Self {
        Self {
            vtxos: RwLock::new(Vec::new()),
        }
    }

    async fn seed_vtxos(&self, vtxos: Vec<Vtxo>) {
        let mut store = self.vtxos.write().await;
        store.extend(vtxos);
    }
}

#[async_trait]
impl VtxoRepository for InMemoryVtxoRepo {
    async fn add_vtxos(&self, vtxos: &[Vtxo]) -> ArkResult<()> {
        let mut store = self.vtxos.write().await;
        for v in vtxos {
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
        let (mut sp, mut st) = (Vec::new(), Vec::new());
        for v in store.iter().filter(|v| v.pubkey == pubkey) {
            if v.spent || v.swept {
                st.push(v.clone());
            } else {
                sp.push(v.clone());
            }
        }
        Ok((sp, st))
    }
    async fn spend_vtxos(&self, spent: &[(VtxoOutpoint, String)], ark_txid: &str) -> ArkResult<()> {
        let mut store = self.vtxos.write().await;
        for (op, by) in spent {
            if let Some(v) = store.iter_mut().find(|v| v.outpoint == *op) {
                v.spent = true;
                v.spent_by = by.clone();
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
        _: &XOnlyPublicKey,
        _: &[Intent],
        _: &[BoardingInput],
    ) -> ArkResult<CommitmentTxResult> {
        Ok(CommitmentTxResult {
            commitment_tx: String::new(),
            vtxo_tree: vec![],
            connector_address: String::new(),
            connectors: vec![],
        })
    }
    async fn verify_forfeit_txs(
        &self,
        _: &[Vtxo],
        _: &arkd_core::FlatTxTree,
        _: &[String],
    ) -> ArkResult<Vec<ValidForfeitTx>> {
        Ok(vec![])
    }
}

struct MockCache;
#[async_trait]
impl CacheService for MockCache {
    async fn set(&self, _: &str, _: &[u8], _: Option<u64>) -> ArkResult<()> {
        Ok(())
    }
    async fn get(&self, _: &str) -> ArkResult<Option<Vec<u8>>> {
        Ok(None)
    }
    async fn delete(&self, _: &str) -> ArkResult<bool> {
        Ok(false)
    }
}

struct MockEvents;
#[async_trait]
impl EventPublisher for MockEvents {
    async fn publish_event(&self, _: ArkEvent) -> ArkResult<()> {
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

// ─── Collaborative Exit Tests ───────────────────────────────────────

#[tokio::test]
async fn test_collaborative_exit_flow() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());

    // Seed spendable VTXOs
    let vtxo = Vtxo::new(
        VtxoOutpoint::new("exit_tx1".to_string(), 0),
        500_000,
        "pk_exiter".to_string(),
    );
    vtxo_repo.seed_vtxos(vec![vtxo]).await;

    let service = build_service(vtxo_repo.clone());
    let requester_pk = test_xonly_pubkey();

    let request = CollaborativeExitRequest {
        vtxo_ids: vec![VtxoOutpoint::new("exit_tx1".to_string(), 0)],
        destination: test_address(),
    };

    let exit = service
        .request_collaborative_exit(request, requester_pk)
        .await
        .unwrap();
    assert_eq!(exit.exit_type, ExitType::Collaborative);
    assert_eq!(exit.status, ExitStatus::Pending);
    assert_eq!(exit.amount, bitcoin::Amount::from_sat(500_000));

    // Retrieve the exit
    let fetched = service.get_exit(exit.id).await.unwrap();
    assert_eq!(fetched.id, exit.id);

    // Complete the exit
    service
        .complete_exit(exit.id, bitcoin::Amount::from_sat(1_000))
        .await
        .unwrap();
    let completed = service.get_exit(exit.id).await.unwrap();
    assert_eq!(completed.status, ExitStatus::Completed);
}

#[tokio::test]
async fn test_collaborative_exit_no_vtxos() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let service = build_service(vtxo_repo);
    let requester_pk = test_xonly_pubkey();

    let request = CollaborativeExitRequest {
        vtxo_ids: vec![VtxoOutpoint::new("nonexistent".to_string(), 0)],
        destination: test_address(),
    };

    let result = service
        .request_collaborative_exit(request, requester_pk)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_collaborative_exit_spent_vtxo() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());

    let mut vtxo = Vtxo::new(
        VtxoOutpoint::new("spent_tx".to_string(), 0),
        100_000,
        "pk_spent".to_string(),
    );
    vtxo.spent = true;
    vtxo_repo.seed_vtxos(vec![vtxo]).await;

    let service = build_service(vtxo_repo);
    let requester_pk = test_xonly_pubkey();

    let request = CollaborativeExitRequest {
        vtxo_ids: vec![VtxoOutpoint::new("spent_tx".to_string(), 0)],
        destination: test_address(),
    };

    let result = service
        .request_collaborative_exit(request, requester_pk)
        .await;
    assert!(result.is_err());
}

// ─── Unilateral Exit Tests ──────────────────────────────────────────

#[tokio::test]
async fn test_unilateral_exit_flow() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());

    let vtxo = Vtxo::new(
        VtxoOutpoint::new("uni_tx1".to_string(), 0),
        300_000,
        "pk_uni".to_string(),
    );
    vtxo_repo.seed_vtxos(vec![vtxo]).await;

    let service = build_service(vtxo_repo);
    let requester_pk = test_xonly_pubkey();

    let request = UnilateralExitRequest {
        vtxo_id: VtxoOutpoint::new("uni_tx1".to_string(), 0),
        destination: test_address(),
        fee_rate_sat_vb: 10,
    };

    let exit = service
        .request_unilateral_exit(request, requester_pk)
        .await
        .unwrap();
    assert_eq!(exit.exit_type, ExitType::Unilateral);
    assert_eq!(exit.status, ExitStatus::Pending);
    assert_eq!(exit.amount, bitcoin::Amount::from_sat(300_000));
    // claimable_height = 800_000 (mock block height) + 512 (default delay)
    assert_eq!(exit.claimable_height, Some(800_512));
}

#[tokio::test]
async fn test_unilateral_exit_not_found() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let service = build_service(vtxo_repo);
    let requester_pk = test_xonly_pubkey();

    let request = UnilateralExitRequest {
        vtxo_id: VtxoOutpoint::new("nope".to_string(), 0),
        destination: test_address(),
        fee_rate_sat_vb: 10,
    };

    assert!(service
        .request_unilateral_exit(request, requester_pk)
        .await
        .is_err());
}

// ─── Cancel Exit Tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_cancel_exit() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let vtxo = Vtxo::new(
        VtxoOutpoint::new("cancel_tx".to_string(), 0),
        100_000,
        "pk".to_string(),
    );
    vtxo_repo.seed_vtxos(vec![vtxo]).await;

    let service = build_service(vtxo_repo);
    let requester_pk = test_xonly_pubkey();

    let request = CollaborativeExitRequest {
        vtxo_ids: vec![VtxoOutpoint::new("cancel_tx".to_string(), 0)],
        destination: test_address(),
    };

    let exit = service
        .request_collaborative_exit(request, requester_pk)
        .await
        .unwrap();
    service.cancel_exit(exit.id).await.unwrap();

    let cancelled = service.get_exit(exit.id).await.unwrap();
    assert_eq!(cancelled.status, ExitStatus::Cancelled);
}

#[tokio::test]
async fn test_cancel_nonexistent_exit() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());
    let service = build_service(vtxo_repo);
    assert!(service.cancel_exit(uuid::Uuid::new_v4()).await.is_err());
}

// ─── Exit Domain Model Tests ────────────────────────────────────────

#[tokio::test]
async fn test_exit_blocks_until_claimable() {
    let mut exit = Exit::unilateral(
        VtxoOutpoint::new("blk_tx".to_string(), 0),
        test_address(),
        test_xonly_pubkey(),
        bitcoin::Amount::from_sat(100_000),
        1000,
    );

    assert_eq!(exit.blocks_until_claimable(900), Some(100));
    assert_eq!(exit.blocks_until_claimable(1000), None);
    assert_eq!(exit.blocks_until_claimable(1100), None);

    exit.mark_processing();
    use bitcoin::hashes::Hash;
    let txid =
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32]));
    exit.mark_waiting_timelock(txid);

    assert!(!exit.can_claim(999));
    assert!(exit.can_claim(1000));
}

#[tokio::test]
async fn test_get_pending_collaborative_exits() {
    let vtxo_repo = Arc::new(InMemoryVtxoRepo::new());

    // Seed multiple VTXOs
    for i in 0..3 {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new(format!("pending_tx_{i}"), 0),
            100_000 * (i as u64 + 1),
            "pk".to_string(),
        );
        vtxo_repo.seed_vtxos(vec![vtxo]).await;
    }

    let service = build_service(vtxo_repo);
    let pk = test_xonly_pubkey();

    // Create 3 exits
    for i in 0..3 {
        let request = CollaborativeExitRequest {
            vtxo_ids: vec![VtxoOutpoint::new(format!("pending_tx_{i}"), 0)],
            destination: test_address(),
        };
        service
            .request_collaborative_exit(request, pk)
            .await
            .unwrap();
    }

    let pending = service.get_pending_collaborative_exits().await;
    assert_eq!(pending.len(), 3);
}
