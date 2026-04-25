//! Live in-memory VTXO store (issue #535).
//!
//! Holds the ephemeral, hot-path VTXO map used during round validation. The
//! map stores **both** [`VtxoVersion::Transparent`] and
//! [`VtxoVersion::Confidential`] entries via the same [`Vtxo`] type — issue
//! #530 already gave `Vtxo` a `confidential: Option<ConfidentialPayload>`
//! field, so this store does not need a separate enum. Variant-aware
//! accessors ([`LiveVtxoStore::amount_or_commitment`],
//! [`LiveVtxoStore::nullifier_of`]) read the right field per variant.
//!
//! # Indexing model
//!
//! Two indexes are maintained, each behind its own sharded `RwLock` so
//! readers don't serialise on a single mutex (10K-participant rounds would
//! otherwise queue every lookup behind a writer):
//!
//! - **Primary** — [`VtxoOutpoint`] -> [`Vtxo`]. Source of truth for the
//!   stored entry. Sharded by the first byte of the txid hex string.
//!
//! - **Secondary** — `nullifier ([u8; 32])` -> [`VtxoOutpoint`]. Used by the
//!   confidential validation hot path to resolve `nullifier -> (vtxo_id,
//!   amount_commitment)` without scanning the primary map. Sharded by the
//!   first byte of the nullifier (uniformly distributed because nullifiers
//!   are HMAC-SHA256 outputs per ADR-0002).
//!
//! # Why the secondary index is populated *lazily on spend*
//!
//! Confidential VTXO nullifiers are derived from the **owner's secret key**
//! per ADR-0002 (`HMAC-SHA256(sk, dst || ver || vtxo_id)`). The operator
//! cannot precompute them at insert time — it has no access to the user's
//! secret key. So:
//!
//! 1. When a confidential VTXO is first inserted (output of a round), only
//!    the primary `outpoint -> vtxo` mapping is populated. The
//!    [`ConfidentialPayload`] *carries* a nullifier field, but that field
//!    holds the **OUTPUT-side** nullifier created by the sender — not the
//!    nullifier that this VTXO will eventually be spent under.
//!
//!    However, that output-side nullifier IS the one the spender will
//!    reveal when they spend this VTXO (it's the spent-set marker). So we
//!    eagerly populate the index from the payload at insert time too — see
//!    [`LiveVtxoStore::insert`] — and we get the same answer either way.
//!
//! 2. On spend observation ([`LiveVtxoStore::observe_spend`]), the spender
//!    submits a transaction declaring `(input_vtxo_outpoint, nullifier)`.
//!    We confirm the nullifier matches (or learn it for the first time if
//!    we hadn't observed the output-side payload — e.g. transparent inputs
//!    being mixed with confidential outputs in the same round). The
//!    secondary index is updated under the writer lock.
//!
//! This dual-trigger model means the index is correct in both cases:
//! whether the operator first sees the **output** of round N or the
//! **spend** of that VTXO in round N+1.
//!
//! # Eviction / rehydration
//!
//! Matching `NullifierSet`, the on-process model is bulk-load at startup
//! and lazy rehydrate on miss. Concrete eviction (e.g. drop fully-swept
//! VTXOs) is the caller's responsibility — typically a sweeper service —
//! and is exposed via [`LiveVtxoStore::remove`]. A pluggable
//! [`VtxoBackend`] trait lets a Postgres / SQLite repo back the store
//! without `dark-live-store` depending on `dark-db`. Implementations live
//! in `dark-db`.
//!
//! # Observability
//!
//! Every public lookup updates `dark_core::metrics::LIVE_VTXO_*` counters
//! / gauges and feeds the `live_vtxo_lookup_latency_seconds` histogram via
//! a RAII timer. See [`crate::vtxo_store`] for the metric inventory.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use dark_core::domain::vtxo::{AmountOrCommitment, Vtxo, VtxoOutpoint, NULLIFIER_LEN};
use dark_core::error::ArkResult;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Shard count for both primary and secondary maps.
///
/// Power-of-two so the shard index is a single mask, not a divide. 16 is
/// the same factor used by `NullifierSet`; benchmarks at 1M / 10M scale
/// show diminishing returns past 16.
pub const VTXO_SHARD_COUNT: usize = 16;
const VTXO_SHARD_MASK: usize = VTXO_SHARD_COUNT - 1;

/// 32-byte nullifier — alias for clarity at API boundaries.
///
/// Re-exported here so callers can use the live VTXO store without
/// importing the `nullifier_set` module too.
pub type Nullifier = [u8; NULLIFIER_LEN];

/// Optional storage backend used for crash-recovery / rehydration of the
/// live VTXO store.
///
/// `dark-live-store` does not depend on `dark-db`; an implementation lives
/// in `dark-db` and is plugged in at process start. The trait is
/// intentionally narrow: just the queries needed to repopulate the
/// in-memory map.
///
/// `dark-db` already exposes `VtxoRepository::get_vtxos`; thin adapters
/// can satisfy `VtxoBackend` by delegating without exposing the full
/// repository surface to the live store.
#[async_trait]
pub trait VtxoBackend: Send + Sync {
    /// Read every currently-spendable VTXO from the persistent store, in
    /// any order. Called once during [`LiveVtxoStore::load_from_db`] at
    /// process start.
    async fn load_all_spendable(&self) -> ArkResult<Vec<Vtxo>>;

    /// Look up a single VTXO by its outpoint.
    ///
    /// Returns `Ok(None)` for a non-existent outpoint. Used by lazy
    /// rehydration on cache miss; if the caller did not configure a
    /// backend, miss is just a miss.
    async fn fetch_by_outpoint(&self, outpoint: &VtxoOutpoint) -> ArkResult<Option<Vtxo>>;

    /// Look up a confidential VTXO by its nullifier.
    ///
    /// Default implementation returns `Ok(None)` — implementations that
    /// know how to query the `confidential_nullifier` index (e.g. via
    /// migration 008's partial unique index) should override.
    async fn fetch_by_nullifier(&self, nullifier: &Nullifier) -> ArkResult<Option<Vtxo>> {
        let _ = nullifier;
        Ok(None)
    }
}

/// Pick the shard for a VTXO outpoint via the first byte of the txid hex.
///
/// txids are SHA256 hashes formatted as 64-char lowercase hex; their
/// first byte is uniformly distributed in `[0..255]`. Empty txid (the
/// "note" case) lands in shard 0, which is fine — note VTXOs are rare on
/// the hot path.
#[inline]
fn outpoint_shard(outpoint: &VtxoOutpoint) -> usize {
    outpoint.txid.as_bytes().first().copied().unwrap_or(0) as usize & VTXO_SHARD_MASK
}

/// Pick the shard for a nullifier via its first byte.
#[inline]
fn nullifier_shard(n: &Nullifier) -> usize {
    n[0] as usize & VTXO_SHARD_MASK
}

/// Sharded VTXO maps — one `RwLock<HashMap>` per shard.
struct PrimaryShards {
    shards: Vec<RwLock<HashMap<VtxoOutpoint, Vtxo>>>,
}

impl PrimaryShards {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(VTXO_SHARD_COUNT);
        for _ in 0..VTXO_SHARD_COUNT {
            shards.push(RwLock::new(HashMap::new()));
        }
        Self { shards }
    }
}

/// Sharded nullifier-index maps — one `RwLock<HashMap>` per shard.
struct NullifierShards {
    shards: Vec<RwLock<HashMap<Nullifier, VtxoOutpoint>>>,
}

impl NullifierShards {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(VTXO_SHARD_COUNT);
        for _ in 0..VTXO_SHARD_COUNT {
            shards.push(RwLock::new(HashMap::new()));
        }
        Self { shards }
    }
}

/// Live VTXO store: outpoint -> Vtxo plus a nullifier -> outpoint
/// secondary index.
///
/// Construct with [`LiveVtxoStore::new`] for an empty store, or
/// [`LiveVtxoStore::load_from_db`] to bulk-hydrate from a backend at
/// process start. Hot-path operations are sharded so concurrent readers
/// across distinct VTXOs never serialise.
pub struct LiveVtxoStore {
    primary: Arc<PrimaryShards>,
    by_nullifier: Arc<NullifierShards>,
    /// Optional backend for crash-recovery / rehydration. `None` means
    /// the store is self-contained (typical in unit tests).
    backend: Option<Arc<dyn VtxoBackend>>,
}

impl LiveVtxoStore {
    /// Create an empty store with no backend. Lookups that miss return
    /// `None`; nothing is fetched lazily.
    pub fn new() -> Self {
        Self {
            primary: Arc::new(PrimaryShards::new()),
            by_nullifier: Arc::new(NullifierShards::new()),
            backend: None,
        }
    }

    /// Create an empty store wired to a [`VtxoBackend`].
    ///
    /// Lookups that miss the in-memory map will consult the backend and
    /// (on hit) populate the in-memory caches. This matches the
    /// `NullifierSet::load_from_db` pattern: bulk hydrate at start,
    /// lazy rehydrate on stragglers.
    pub fn with_backend(backend: Arc<dyn VtxoBackend>) -> Self {
        Self {
            primary: Arc::new(PrimaryShards::new()),
            by_nullifier: Arc::new(NullifierShards::new()),
            backend: Some(backend),
        }
    }

    /// Bulk-hydrate the store from the backend.
    ///
    /// Called once at process start. Iterates every spendable VTXO from
    /// the backend, drops them into the appropriate primary shard, and
    /// populates the nullifier index for any confidential entry. Time
    /// complexity is O(n / shard_count) per shard write — both shard
    /// arrays are pre-bucketed to avoid taking each shard lock once per
    /// row.
    pub async fn load_from_db(backend: Arc<dyn VtxoBackend>) -> ArkResult<Self> {
        let store = Self::with_backend(Arc::clone(&backend));
        let all = backend.load_all_spendable().await?;
        let count = all.len();

        // Bucket by primary shard so each shard lock is taken once.
        let mut primary_buckets: Vec<Vec<(VtxoOutpoint, Vtxo)>> =
            (0..VTXO_SHARD_COUNT).map(|_| Vec::new()).collect();
        let mut nullifier_buckets: Vec<Vec<(Nullifier, VtxoOutpoint)>> =
            (0..VTXO_SHARD_COUNT).map(|_| Vec::new()).collect();
        let mut confidential_count: i64 = 0;

        for vtxo in all {
            let outpoint = vtxo.outpoint.clone();
            if let Some(n) = vtxo.nullifier().copied() {
                nullifier_buckets[nullifier_shard(&n)].push((n, outpoint.clone()));
                confidential_count += 1;
            }
            primary_buckets[outpoint_shard(&outpoint)].push((outpoint, vtxo));
        }

        for (idx, bucket) in primary_buckets.into_iter().enumerate() {
            if bucket.is_empty() {
                continue;
            }
            let mut guard = store.primary.shards[idx].write().await;
            for (op, v) in bucket {
                guard.insert(op, v);
            }
        }

        for (idx, bucket) in nullifier_buckets.into_iter().enumerate() {
            if bucket.is_empty() {
                continue;
            }
            let mut guard = store.by_nullifier.shards[idx].write().await;
            for (n, op) in bucket {
                guard.insert(n, op);
            }
        }

        dark_core::metrics::LIVE_VTXOS_TOTAL.set(count as i64);
        dark_core::metrics::LIVE_VTXOS_CONFIDENTIAL_TOTAL.set(confidential_count);
        info!(
            loaded = count,
            confidential = confidential_count,
            "LiveVtxoStore hydrated from backend"
        );
        Ok(store)
    }

    // -----------------------------------------------------------------
    // Mutators
    // -----------------------------------------------------------------

    /// Insert (or overwrite) a VTXO.
    ///
    /// If the VTXO is confidential ([`Vtxo::is_confidential`]), the
    /// secondary nullifier index is also populated from
    /// [`Vtxo::nullifier`]. This is the *eager* arm of the dual-trigger
    /// design described at the module level: when the operator first
    /// sees a confidential output it can index by nullifier immediately
    /// because the payload carries the nullifier the spender will reveal.
    pub async fn insert(&self, vtxo: Vtxo) -> ArkResult<()> {
        let _timer = LookupTimer::start_insert();
        let outpoint = vtxo.outpoint.clone();
        let nullifier = vtxo.nullifier().copied();
        let was_confidential = vtxo.is_confidential();

        // 1) Primary insert under the outpoint shard. Capture the
        //    previous variant flag so we can adjust the gauges
        //    correctly: a fresh insert bumps both totals; an overwrite
        //    of the same variant is a no-op; an overwrite that flips
        //    the variant moves the confidential gauge by ±1.
        let primary_shard = &self.primary.shards[outpoint_shard(&outpoint)];
        let prev_state = {
            let mut guard = primary_shard.write().await;
            guard
                .insert(outpoint.clone(), vtxo)
                .map(|p| p.is_confidential())
        };

        // 2) Secondary index, if this is a confidential VTXO.
        if let Some(n) = nullifier {
            let null_shard = &self.by_nullifier.shards[nullifier_shard(&n)];
            null_shard.write().await.insert(n, outpoint);
        }

        // 3) Gauge maintenance.
        match prev_state {
            None => {
                dark_core::metrics::LIVE_VTXOS_TOTAL.inc();
                if was_confidential {
                    dark_core::metrics::LIVE_VTXOS_CONFIDENTIAL_TOTAL.inc();
                }
            }
            Some(prev_was_confidential) if prev_was_confidential != was_confidential => {
                if was_confidential {
                    dark_core::metrics::LIVE_VTXOS_CONFIDENTIAL_TOTAL.inc();
                } else {
                    dark_core::metrics::LIVE_VTXOS_CONFIDENTIAL_TOTAL.dec();
                }
            }
            Some(_) => { /* same-variant overwrite, no gauge change */ }
        }
        Ok(())
    }

    /// Remove a VTXO from both primary and secondary indexes.
    ///
    /// Called by sweepers / round-finalizers that observe a VTXO is no
    /// longer spendable. Returns `Ok(true)` if anything was removed,
    /// `Ok(false)` if the outpoint was unknown.
    pub async fn remove(&self, outpoint: &VtxoOutpoint) -> ArkResult<bool> {
        let primary_shard = &self.primary.shards[outpoint_shard(outpoint)];
        let removed = primary_shard.write().await.remove(outpoint);
        let Some(vtxo) = removed else {
            return Ok(false);
        };

        if let Some(n) = vtxo.nullifier().copied() {
            let null_shard = &self.by_nullifier.shards[nullifier_shard(&n)];
            // Only remove the nullifier index entry if it still points at
            // this outpoint. A spend that re-bound the nullifier would
            // have updated it; we shouldn't accidentally clobber that.
            let mut guard = null_shard.write().await;
            if let Some(current) = guard.get(&n) {
                if current == outpoint {
                    guard.remove(&n);
                }
            }
            dark_core::metrics::LIVE_VTXOS_CONFIDENTIAL_TOTAL.dec();
        }
        dark_core::metrics::LIVE_VTXOS_TOTAL.dec();
        debug!(?outpoint, "LiveVtxoStore::remove");
        Ok(true)
    }

    /// Record an observed spend.
    ///
    /// The spend transaction declares which VTXO it spends (`outpoint`)
    /// AND, for confidential inputs, the revealed `nullifier`. This is
    /// the *lazy* arm of the dual-trigger design: even if the original
    /// confidential output was never observed by this operator (e.g.
    /// during a hand-off / restart), the spend tx still teaches us the
    /// `nullifier -> outpoint` mapping which the validator will need on
    /// the next confirmation.
    ///
    /// Returns `Ok(true)` if the index was newly populated (or updated),
    /// `Ok(false)` if it already pointed at the same outpoint.
    pub async fn observe_spend(
        &self,
        outpoint: &VtxoOutpoint,
        nullifier: &Nullifier,
    ) -> ArkResult<bool> {
        let null_shard = &self.by_nullifier.shards[nullifier_shard(nullifier)];
        let mut guard = null_shard.write().await;
        let updated = match guard.get(nullifier) {
            Some(existing) if existing == outpoint => false,
            Some(existing) => {
                // The nullifier already points at a *different* outpoint.
                // This is an invariant violation: a nullifier is bound
                // to exactly one VTXO. We log loudly but still update so
                // the latest observation wins (matching at-least-once
                // semantics from the indexer).
                warn!(
                    ?existing,
                    new = ?outpoint,
                    nullifier_hex = %hex::encode(nullifier),
                    "LiveVtxoStore: nullifier reassignment — possible double-spend"
                );
                guard.insert(*nullifier, outpoint.clone());
                true
            }
            None => {
                guard.insert(*nullifier, outpoint.clone());
                true
            }
        };
        Ok(updated)
    }

    // -----------------------------------------------------------------
    // Read accessors
    // -----------------------------------------------------------------

    /// Look up a VTXO by its outpoint.
    ///
    /// Hot path. On miss with a configured [`VtxoBackend`], the backend
    /// is consulted and the result cached before returning.
    pub async fn get(&self, outpoint: &VtxoOutpoint) -> ArkResult<Option<Vtxo>> {
        let _timer = LookupTimer::start();
        dark_core::metrics::LIVE_VTXO_LOOKUPS_TOTAL.inc();

        let primary_shard = &self.primary.shards[outpoint_shard(outpoint)];
        if let Some(v) = primary_shard.read().await.get(outpoint) {
            dark_core::metrics::LIVE_VTXO_LOOKUP_HITS_TOTAL.inc();
            return Ok(Some(v.clone()));
        }

        // Lazy rehydrate from backend if configured.
        if let Some(backend) = self.backend.as_ref() {
            if let Some(v) = backend.fetch_by_outpoint(outpoint).await? {
                self.cache_after_miss(v.clone()).await;
                dark_core::metrics::LIVE_VTXO_LOOKUP_HITS_TOTAL.inc();
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    /// Look up a VTXO by its nullifier (confidential variant only).
    ///
    /// On hit, returns the stored [`Vtxo`]. On miss with a configured
    /// backend, the backend is consulted via `fetch_by_nullifier` and
    /// the result cached. The nullifier-side hit-rate counter is
    /// incremented separately so operators can tell the two lookup
    /// modes apart in their dashboards.
    pub async fn get_by_nullifier(&self, nullifier: &Nullifier) -> ArkResult<Option<Vtxo>> {
        let _timer = LookupTimer::start();
        dark_core::metrics::LIVE_VTXO_LOOKUPS_TOTAL.inc();
        dark_core::metrics::LIVE_VTXO_NULLIFIER_LOOKUPS_TOTAL.inc();

        let null_shard = &self.by_nullifier.shards[nullifier_shard(nullifier)];
        let outpoint_opt = null_shard.read().await.get(nullifier).cloned();
        if let Some(outpoint) = outpoint_opt {
            // Resolve the primary entry under its own shard.
            let primary_shard = &self.primary.shards[outpoint_shard(&outpoint)];
            if let Some(v) = primary_shard.read().await.get(&outpoint) {
                dark_core::metrics::LIVE_VTXO_LOOKUP_HITS_TOTAL.inc();
                dark_core::metrics::LIVE_VTXO_NULLIFIER_HITS_TOTAL.inc();
                return Ok(Some(v.clone()));
            }
            // Index points at a primary entry that's not in the cache —
            // could happen if the primary entry was evicted but the
            // index lingered. Try the backend before giving up.
        }

        if let Some(backend) = self.backend.as_ref() {
            if let Some(v) = backend.fetch_by_nullifier(nullifier).await? {
                self.cache_after_miss(v.clone()).await;
                dark_core::metrics::LIVE_VTXO_LOOKUP_HITS_TOTAL.inc();
                dark_core::metrics::LIVE_VTXO_NULLIFIER_HITS_TOTAL.inc();
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    /// Variant-aware accessor: returns the plaintext amount or the
    /// Pedersen commitment for the VTXO under `outpoint`, without
    /// cloning the whole record.
    ///
    /// The result is owned ([`OwnedAmountOrCommitment`]) rather than a
    /// borrow because the inner read guard is released before return —
    /// holding it across the `await` boundary would risk lock starvation
    /// in async callers.
    pub async fn amount_or_commitment(
        &self,
        outpoint: &VtxoOutpoint,
    ) -> ArkResult<Option<OwnedAmountOrCommitment>> {
        let _timer = LookupTimer::start();
        dark_core::metrics::LIVE_VTXO_LOOKUPS_TOTAL.inc();
        let primary_shard = &self.primary.shards[outpoint_shard(outpoint)];
        let owned = {
            let guard = primary_shard.read().await;
            guard.get(outpoint).map(|v| match v.amount_or_commitment() {
                AmountOrCommitment::Amount(a) => OwnedAmountOrCommitment::Amount(a),
                AmountOrCommitment::Commitment(c) => OwnedAmountOrCommitment::Commitment(*c),
            })
        };
        if owned.is_some() {
            dark_core::metrics::LIVE_VTXO_LOOKUP_HITS_TOTAL.inc();
        }
        Ok(owned)
    }

    /// Variant-aware accessor: returns the 32-byte nullifier of a
    /// confidential VTXO under `outpoint`, or `None` if the VTXO is
    /// transparent / unknown. Reads the right field per
    /// [`Vtxo::version`].
    pub async fn nullifier_of(&self, outpoint: &VtxoOutpoint) -> ArkResult<Option<Nullifier>> {
        let primary_shard = &self.primary.shards[outpoint_shard(outpoint)];
        Ok(primary_shard
            .read()
            .await
            .get(outpoint)
            .and_then(|v| v.nullifier().copied()))
    }

    /// Returns `true` if the secondary nullifier index has an entry for
    /// the given nullifier — useful for the validation pipeline (#538)
    /// to check membership without materialising the full VTXO.
    pub async fn nullifier_index_contains(&self, nullifier: &Nullifier) -> bool {
        let _timer = LookupTimer::start();
        dark_core::metrics::LIVE_VTXO_NULLIFIER_LOOKUPS_TOTAL.inc();
        let null_shard = &self.by_nullifier.shards[nullifier_shard(nullifier)];
        let hit = null_shard.read().await.contains_key(nullifier);
        if hit {
            dark_core::metrics::LIVE_VTXO_NULLIFIER_HITS_TOTAL.inc();
        }
        hit
    }

    /// Total in-memory primary count across all shards.
    pub async fn len(&self) -> usize {
        let mut total = 0;
        for shard in &self.primary.shards {
            total += shard.read().await.len();
        }
        total
    }

    /// `true` iff every primary shard is empty.
    pub async fn is_empty(&self) -> bool {
        for shard in &self.primary.shards {
            if !shard.read().await.is_empty() {
                return false;
            }
        }
        true
    }

    /// Total in-memory nullifier-index count across all shards.
    pub async fn nullifier_index_len(&self) -> usize {
        let mut total = 0;
        for shard in &self.by_nullifier.shards {
            total += shard.read().await.len();
        }
        total
    }

    // -----------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------

    /// Populate the in-memory caches after a backend hit.
    ///
    /// Pulled out of `get` / `get_by_nullifier` so they share the same
    /// caching code path (and so the gauge bumps are consistent).
    async fn cache_after_miss(&self, vtxo: Vtxo) {
        let outpoint = vtxo.outpoint.clone();
        let was_confidential = vtxo.is_confidential();
        let nullifier = vtxo.nullifier().copied();
        let primary_shard = &self.primary.shards[outpoint_shard(&outpoint)];
        let inserted_new = {
            let mut guard = primary_shard.write().await;
            guard.insert(outpoint.clone(), vtxo).is_none()
        };
        if let Some(n) = nullifier {
            let null_shard = &self.by_nullifier.shards[nullifier_shard(&n)];
            null_shard.write().await.insert(n, outpoint);
        }
        if inserted_new {
            dark_core::metrics::LIVE_VTXOS_TOTAL.inc();
            if was_confidential {
                dark_core::metrics::LIVE_VTXOS_CONFIDENTIAL_TOTAL.inc();
            }
        }
    }
}

impl Default for LiveVtxoStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Owned counterpart of [`AmountOrCommitment`] for callers that drop the
/// underlying read guard before returning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedAmountOrCommitment {
    /// Plaintext amount in satoshis (transparent variant).
    Amount(u64),
    /// 33-byte Pedersen commitment (confidential variant).
    Commitment([u8; dark_core::domain::vtxo::PEDERSEN_COMMITMENT_LEN]),
}

/// RAII timer for lookup-latency histogram updates.
///
/// Drop semantics ensure the timer fires even if the caller bails out
/// early via `?`.
struct LookupTimer {
    start: Instant,
}

impl LookupTimer {
    fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Insert latency lands in the same histogram so a single dashboard
    /// graph captures the whole hot path. We can split via a label
    /// later if the buckets are ever overwhelmed.
    fn start_insert() -> Self {
        Self::start()
    }
}

impl Drop for LookupTimer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        dark_core::metrics::LIVE_VTXO_LOOKUP_LATENCY.observe(elapsed);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dark_core::domain::vtxo::{
        ConfidentialPayload, EPHEMERAL_PUBKEY_LEN, PEDERSEN_COMMITMENT_LEN,
    };
    use tokio::sync::Mutex;

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    fn make_outpoint(seed: u8) -> VtxoOutpoint {
        // Use a hex-shaped txid so outpoint_shard sees realistic input.
        let txid = format!("{:02x}{:062x}", seed, seed as u32);
        VtxoOutpoint::new(txid, seed as u32)
    }

    fn make_payload(seed: u8) -> ConfidentialPayload {
        ConfidentialPayload::new(
            [seed; PEDERSEN_COMMITMENT_LEN],
            vec![seed; 64],
            [seed.wrapping_add(1); NULLIFIER_LEN],
            [seed.wrapping_add(2); EPHEMERAL_PUBKEY_LEN],
        )
    }

    fn make_transparent(seed: u8, amount: u64) -> Vtxo {
        Vtxo::new(make_outpoint(seed), amount, format!("pk-{seed}"))
    }

    fn make_confidential(seed: u8) -> Vtxo {
        Vtxo::new_confidential(
            make_outpoint(seed),
            format!("pk-{seed}"),
            make_payload(seed),
        )
    }

    // -----------------------------------------------------------------
    // Mock backend for hydration / lazy-fetch tests
    // -----------------------------------------------------------------

    struct MockBackend {
        rows: Mutex<HashMap<VtxoOutpoint, Vtxo>>,
    }

    impl MockBackend {
        fn new(initial: Vec<Vtxo>) -> Self {
            let mut rows = HashMap::new();
            for v in initial {
                rows.insert(v.outpoint.clone(), v);
            }
            Self {
                rows: Mutex::new(rows),
            }
        }
    }

    #[async_trait]
    impl VtxoBackend for MockBackend {
        async fn load_all_spendable(&self) -> ArkResult<Vec<Vtxo>> {
            Ok(self.rows.lock().await.values().cloned().collect())
        }

        async fn fetch_by_outpoint(&self, outpoint: &VtxoOutpoint) -> ArkResult<Option<Vtxo>> {
            Ok(self.rows.lock().await.get(outpoint).cloned())
        }

        async fn fetch_by_nullifier(&self, nullifier: &Nullifier) -> ArkResult<Option<Vtxo>> {
            for v in self.rows.lock().await.values() {
                if v.nullifier() == Some(nullifier) {
                    return Ok(Some(v.clone()));
                }
            }
            Ok(None)
        }
    }

    // -----------------------------------------------------------------
    // Basic mutators
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn empty_store_is_empty() {
        let store = LiveVtxoStore::new();
        assert!(store.is_empty().await);
        assert_eq!(store.len().await, 0);
        assert_eq!(store.nullifier_index_len().await, 0);
        assert!(store.get(&make_outpoint(1)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn insert_transparent_then_get() {
        let store = LiveVtxoStore::new();
        let v = make_transparent(1, 50_000);
        store.insert(v.clone()).await.unwrap();

        let got = store.get(&v.outpoint).await.unwrap().unwrap();
        assert_eq!(got, v);
        assert!(got.is_transparent());
        // Nullifier index must NOT be populated for transparent.
        assert_eq!(store.nullifier_index_len().await, 0);
    }

    #[tokio::test]
    async fn insert_confidential_populates_nullifier_index() {
        let store = LiveVtxoStore::new();
        let v = make_confidential(7);
        let nullifier = *v.nullifier().expect("confidential VTXO has nullifier");
        store.insert(v.clone()).await.unwrap();

        // Both indexes are populated immediately.
        assert!(store.nullifier_index_contains(&nullifier).await);
        let by_null = store.get_by_nullifier(&nullifier).await.unwrap().unwrap();
        assert_eq!(by_null, v);
        let by_outpoint = store.get(&v.outpoint).await.unwrap().unwrap();
        assert_eq!(by_outpoint, v);
    }

    #[tokio::test]
    async fn mixed_variants_coexist() {
        // Per #535: extend the in-memory map to store BOTH variants.
        let store = LiveVtxoStore::new();
        let t = make_transparent(1, 1_000);
        let c = make_confidential(2);
        store.insert(t.clone()).await.unwrap();
        store.insert(c.clone()).await.unwrap();

        assert_eq!(store.len().await, 2);
        // Each fetched back as its original variant.
        assert!(store
            .get(&t.outpoint)
            .await
            .unwrap()
            .unwrap()
            .is_transparent());
        assert!(store
            .get(&c.outpoint)
            .await
            .unwrap()
            .unwrap()
            .is_confidential());

        // Nullifier index only sees the confidential one.
        assert_eq!(store.nullifier_index_len().await, 1);
        let null_c = *c.nullifier().unwrap();
        assert!(store.nullifier_index_contains(&null_c).await);
    }

    #[tokio::test]
    async fn observe_spend_populates_index_lazily() {
        // The "lazy on spend" path: a transparent-output VTXO is later
        // spent confidentially, revealing the nullifier in the spend
        // tx. The store should learn the mapping from `observe_spend`.
        let store = LiveVtxoStore::new();
        let v = make_transparent(0xab, 42_000);
        store.insert(v.clone()).await.unwrap();
        assert_eq!(store.nullifier_index_len().await, 0);

        // Some external observer sees the spend tx and tells us the
        // revealed nullifier.
        let nullifier: Nullifier = [0x33u8; NULLIFIER_LEN];
        let new = store.observe_spend(&v.outpoint, &nullifier).await.unwrap();
        assert!(new, "first observation must report a fresh insert");

        assert!(store.nullifier_index_contains(&nullifier).await);
        // get_by_nullifier resolves to the same VTXO via the index.
        let resolved = store.get_by_nullifier(&nullifier).await.unwrap().unwrap();
        assert_eq!(resolved, v);
    }

    #[tokio::test]
    async fn observe_spend_idempotent_on_same_pair() {
        let store = LiveVtxoStore::new();
        let v = make_transparent(0x10, 1);
        store.insert(v.clone()).await.unwrap();
        let nullifier = [0x99u8; NULLIFIER_LEN];

        let first = store.observe_spend(&v.outpoint, &nullifier).await.unwrap();
        let second = store.observe_spend(&v.outpoint, &nullifier).await.unwrap();
        assert!(first);
        assert!(!second, "repeated spend observation must be a no-op");
    }

    #[tokio::test]
    async fn observe_spend_rebinds_to_new_outpoint() {
        // Defensive — protocol-level a nullifier should bind to one VTXO,
        // but if the store ever sees a re-observation we keep the
        // latest.
        let store = LiveVtxoStore::new();
        let a = make_transparent(0x01, 1);
        let b = make_transparent(0x02, 2);
        store.insert(a.clone()).await.unwrap();
        store.insert(b.clone()).await.unwrap();
        let nullifier = [0xaau8; NULLIFIER_LEN];

        store.observe_spend(&a.outpoint, &nullifier).await.unwrap();
        let updated = store.observe_spend(&b.outpoint, &nullifier).await.unwrap();
        assert!(updated, "rebinding must report change=true");
        // Resolves to the *new* outpoint.
        let v = store.get_by_nullifier(&nullifier).await.unwrap().unwrap();
        assert_eq!(v.outpoint, b.outpoint);
    }

    #[tokio::test]
    async fn remove_clears_both_indexes() {
        let store = LiveVtxoStore::new();
        let v = make_confidential(13);
        let nullifier = *v.nullifier().unwrap();
        store.insert(v.clone()).await.unwrap();
        assert!(store.nullifier_index_contains(&nullifier).await);

        let removed = store.remove(&v.outpoint).await.unwrap();
        assert!(removed);
        assert!(store.get(&v.outpoint).await.unwrap().is_none());
        assert!(!store.nullifier_index_contains(&nullifier).await);
        assert_eq!(store.len().await, 0);
    }

    #[tokio::test]
    async fn remove_keeps_index_when_nullifier_was_rebound() {
        // Edge case: observe_spend has already pointed the nullifier at
        // a different outpoint. Removing the original VTXO must NOT
        // clobber that index entry.
        let store = LiveVtxoStore::new();
        let a = make_confidential(0x10);
        let b = make_outpoint(0x20);
        let nullifier = *a.nullifier().unwrap();
        store.insert(a.clone()).await.unwrap();
        // Rebind the index to a different outpoint.
        store.observe_spend(&b, &nullifier).await.unwrap();
        // Remove A.
        store.remove(&a.outpoint).await.unwrap();
        // Index still resolves to B.
        let null_shard = &store.by_nullifier.shards[nullifier_shard(&nullifier)];
        let guard = null_shard.read().await;
        assert_eq!(guard.get(&nullifier).cloned(), Some(b));
    }

    #[tokio::test]
    async fn remove_unknown_outpoint_returns_false() {
        let store = LiveVtxoStore::new();
        let r = store.remove(&make_outpoint(99)).await.unwrap();
        assert!(!r);
    }

    // -----------------------------------------------------------------
    // Variant-aware accessors
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn amount_or_commitment_dispatches_per_variant() {
        let store = LiveVtxoStore::new();
        let t = make_transparent(1, 9_000);
        let c = make_confidential(2);
        store.insert(t.clone()).await.unwrap();
        store.insert(c.clone()).await.unwrap();

        match store.amount_or_commitment(&t.outpoint).await.unwrap() {
            Some(OwnedAmountOrCommitment::Amount(a)) => assert_eq!(a, 9_000),
            other => panic!("expected Amount, got {other:?}"),
        }

        match store.amount_or_commitment(&c.outpoint).await.unwrap() {
            Some(OwnedAmountOrCommitment::Commitment(bytes)) => {
                assert_eq!(&bytes, c.pedersen_commitment().unwrap());
            }
            other => panic!("expected Commitment, got {other:?}"),
        }

        // Missing outpoint returns None.
        assert!(store
            .amount_or_commitment(&make_outpoint(0xff))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn nullifier_of_returns_payload_field() {
        let store = LiveVtxoStore::new();
        let c = make_confidential(0x55);
        store.insert(c.clone()).await.unwrap();
        let got = store.nullifier_of(&c.outpoint).await.unwrap().unwrap();
        assert_eq!(&got, c.nullifier().unwrap());

        // Transparent: returns None.
        let t = make_transparent(0x66, 1);
        store.insert(t.clone()).await.unwrap();
        assert!(store.nullifier_of(&t.outpoint).await.unwrap().is_none());
    }

    // -----------------------------------------------------------------
    // Index correctness AC
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn index_correctness_after_spend() {
        // AC: after a spend transaction, nullifier -> vtxo_id mapping
        // exists and is correct.
        let store = LiveVtxoStore::new();
        let v = make_confidential(0xee);
        let nullifier = *v.nullifier().unwrap();
        store.insert(v.clone()).await.unwrap();

        // Simulate the spend tx arriving: indexer calls observe_spend
        // with the same nullifier (carried by the spend tx).
        store.observe_spend(&v.outpoint, &nullifier).await.unwrap();

        // The mapping must resolve to the original outpoint.
        let resolved = store.get_by_nullifier(&nullifier).await.unwrap().unwrap();
        assert_eq!(resolved.outpoint, v.outpoint);
        assert_eq!(resolved.pedersen_commitment(), v.pedersen_commitment());
    }

    // -----------------------------------------------------------------
    // Backend hydration / rehydration
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn load_from_db_populates_both_indexes() {
        let mixed: Vec<Vtxo> = vec![
            make_transparent(1, 1_000),
            make_confidential(2),
            make_transparent(3, 2_000),
            make_confidential(4),
        ];
        let backend: Arc<dyn VtxoBackend> = Arc::new(MockBackend::new(mixed.clone()));
        let store = LiveVtxoStore::load_from_db(backend).await.unwrap();

        assert_eq!(store.len().await, 4);
        assert_eq!(store.nullifier_index_len().await, 2);
        for v in &mixed {
            let got = store.get(&v.outpoint).await.unwrap().unwrap();
            assert_eq!(&got, v);
            if let Some(n) = v.nullifier() {
                assert!(store.nullifier_index_contains(n).await);
            }
        }
    }

    #[tokio::test]
    async fn lazy_rehydrate_on_outpoint_miss() {
        let v = make_transparent(0x77, 12_345);
        let backend: Arc<dyn VtxoBackend> = Arc::new(MockBackend::new(vec![v.clone()]));
        // NOTE: don't bulk-load — we want to test the lazy fetch path.
        let store = LiveVtxoStore::with_backend(backend);

        assert_eq!(store.len().await, 0);
        let got = store.get(&v.outpoint).await.unwrap().unwrap();
        assert_eq!(got, v);
        // After the miss, the entry is cached.
        assert_eq!(store.len().await, 1);
        // Second call hits the cache (no backend round-trip).
        let again = store.get(&v.outpoint).await.unwrap().unwrap();
        assert_eq!(again, v);
    }

    #[tokio::test]
    async fn lazy_rehydrate_on_nullifier_miss() {
        let v = make_confidential(0xc1);
        let nullifier = *v.nullifier().unwrap();
        let backend: Arc<dyn VtxoBackend> = Arc::new(MockBackend::new(vec![v.clone()]));
        let store = LiveVtxoStore::with_backend(backend);

        assert!(!store.nullifier_index_contains(&nullifier).await);
        let got = store.get_by_nullifier(&nullifier).await.unwrap().unwrap();
        assert_eq!(got, v);
        // Rehydration populated the primary AND the secondary index.
        assert_eq!(store.len().await, 1);
        assert!(store.nullifier_index_contains(&nullifier).await);
    }

    #[tokio::test]
    async fn miss_with_no_backend_returns_none() {
        let store = LiveVtxoStore::new();
        assert!(store.get(&make_outpoint(0)).await.unwrap().is_none());
        let n = [0u8; NULLIFIER_LEN];
        assert!(store.get_by_nullifier(&n).await.unwrap().is_none());
    }

    // -----------------------------------------------------------------
    // Concurrency
    // -----------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_inserts_are_consistent() {
        const N: usize = 1_000;
        let store = Arc::new(LiveVtxoStore::new());
        let mut handles = Vec::with_capacity(N);
        for i in 0..N {
            let store = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                let v = make_confidential((i % 256) as u8);
                // Spread outpoints out so we don't collide on the same
                // primary key.
                let mut v2 = v.clone();
                v2.outpoint = VtxoOutpoint::new(format!("{i:064x}"), i as u32);
                if let Some(p) = v2.confidential.as_mut() {
                    let mut n = [0u8; NULLIFIER_LEN];
                    n[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    p.nullifier = n;
                }
                store.insert(v2).await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(store.len().await, N);
        assert_eq!(store.nullifier_index_len().await, N);
    }

    // -----------------------------------------------------------------
    // Shard utility
    // -----------------------------------------------------------------

    #[test]
    fn shard_count_is_power_of_two() {
        assert_eq!(VTXO_SHARD_COUNT & (VTXO_SHARD_COUNT - 1), 0);
        assert_eq!(VTXO_SHARD_MASK, VTXO_SHARD_COUNT - 1);
    }

    #[test]
    fn nullifier_shard_only_uses_low_bits() {
        let mut a = [0u8; NULLIFIER_LEN];
        let mut b = [0u8; NULLIFIER_LEN];
        a[0] = 0b0000_0001;
        b[0] = 0b1111_0001;
        assert_eq!(nullifier_shard(&a), nullifier_shard(&b));
    }
}
