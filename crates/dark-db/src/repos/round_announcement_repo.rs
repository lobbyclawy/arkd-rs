//! Round announcement repository — SQLite implementation of
//! `dark_core::ports::RoundAnnouncementRepository` (issue #556).
//!
//! Persists `(round_id, vtxo_id, ephemeral_pubkey)` tuples emitted by every
//! round commit so scanning clients can detect incoming stealth VTXOs without
//! downloading full VTXO data. The schema lives in migration 010.

use async_trait::async_trait;
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::{RoundAnnouncement, RoundAnnouncementRepository};
use sqlx::SqlitePool;
use tracing::debug;

/// SQLite-backed announcement repository.
pub struct SqliteRoundAnnouncementRepository {
    pool: SqlitePool,
}

impl SqliteRoundAnnouncementRepository {
    /// Wrap an existing pool. The caller owns migration execution; this
    /// constructor does not validate that table `round_announcements` exists.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoundAnnouncementRepository for SqliteRoundAnnouncementRepository {
    async fn insert_announcements(
        &self,
        announcements: &[RoundAnnouncement],
        block_height: u32,
    ) -> ArkResult<()> {
        if announcements.is_empty() {
            return Ok(());
        }

        debug!(
            count = announcements.len(),
            block_height, "Inserting round announcements"
        );

        // One transaction so the whole batch lands atomically with the
        // round commit caller.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        for ann in announcements {
            sqlx::query(
                r#"
                INSERT INTO round_announcements
                    (round_id, vtxo_id, ephemeral_pubkey, block_height)
                VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(round_id, vtxo_id) DO UPDATE SET
                    ephemeral_pubkey = excluded.ephemeral_pubkey,
                    block_height = excluded.block_height
                "#,
            )
            .bind(&ann.round_id)
            .bind(&ann.vtxo_id)
            .bind(&ann.ephemeral_pubkey)
            .bind(block_height as i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn list_for_round(&self, round_id: &str) -> ArkResult<Vec<RoundAnnouncement>> {
        debug!(round_id, "Listing round announcements for round");

        let rows = sqlx::query_as::<_, AnnouncementRow>(
            r#"
            SELECT round_id, vtxo_id, ephemeral_pubkey
            FROM round_announcements
            WHERE round_id = ?1
            ORDER BY vtxo_id ASC
            "#,
        )
        .bind(round_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(AnnouncementRow::into_announcement)
            .collect())
    }

    async fn list_after_height(
        &self,
        height: u32,
        limit: u32,
    ) -> ArkResult<Vec<RoundAnnouncement>> {
        debug!(height, limit, "Listing round announcements after height");

        let rows = sqlx::query_as::<_, AnnouncementRow>(
            r#"
            SELECT round_id, vtxo_id, ephemeral_pubkey
            FROM round_announcements
            WHERE block_height > ?1
            ORDER BY block_height ASC, round_id ASC, vtxo_id ASC
            LIMIT ?2
            "#,
        )
        .bind(height as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(AnnouncementRow::into_announcement)
            .collect())
    }

    async fn prune_before(&self, cutoff_block: u32) -> ArkResult<u64> {
        debug!(cutoff_block, "Pruning round announcements before cutoff");

        let result = sqlx::query("DELETE FROM round_announcements WHERE block_height < ?1")
            .bind(cutoff_block as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct AnnouncementRow {
    round_id: String,
    vtxo_id: String,
    ephemeral_pubkey: String,
}

impl AnnouncementRow {
    fn into_announcement(self) -> RoundAnnouncement {
        RoundAnnouncement {
            round_id: self.round_id,
            vtxo_id: self.vtxo_id,
            ephemeral_pubkey: self.ephemeral_pubkey,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn fresh_repo() -> SqliteRoundAnnouncementRepository {
        let db = Database::connect_in_memory().await.unwrap();
        SqliteRoundAnnouncementRepository::new(db.sqlite_pool().unwrap().clone())
    }

    fn make_announcement(
        round_id: &str,
        vtxo_id: &str,
        ephemeral_pubkey: &str,
    ) -> RoundAnnouncement {
        RoundAnnouncement {
            round_id: round_id.to_string(),
            vtxo_id: vtxo_id.to_string(),
            ephemeral_pubkey: ephemeral_pubkey.to_string(),
        }
    }

    #[tokio::test]
    async fn insert_empty_batch_is_a_no_op() {
        let repo = fresh_repo().await;
        repo.insert_announcements(&[], 100).await.unwrap();
        assert!(repo.list_for_round("any").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn insert_and_list_for_round_round_trips() {
        let repo = fresh_repo().await;

        let batch = vec![
            make_announcement("round-1", "vtxo-b:0", "pk_b"),
            make_announcement("round-1", "vtxo-a:0", "pk_a"),
            make_announcement("round-2", "vtxo-c:0", "pk_c"),
        ];
        repo.insert_announcements(&batch, 800_000).await.unwrap();

        let round1 = repo.list_for_round("round-1").await.unwrap();
        // Returned in stable vtxo_id order regardless of insert order.
        assert_eq!(round1.len(), 2);
        assert_eq!(round1[0].vtxo_id, "vtxo-a:0");
        assert_eq!(round1[1].vtxo_id, "vtxo-b:0");

        let round2 = repo.list_for_round("round-2").await.unwrap();
        assert_eq!(round2.len(), 1);
        assert_eq!(round2[0].ephemeral_pubkey, "pk_c");
    }

    #[tokio::test]
    async fn insert_is_idempotent_on_round_id_and_vtxo_id() {
        let repo = fresh_repo().await;

        let ann = make_announcement("round-1", "vtxo-a:0", "pk_a");
        repo.insert_announcements(std::slice::from_ref(&ann), 800_000)
            .await
            .unwrap();

        // Replay the same round commit — must not produce a duplicate row.
        repo.insert_announcements(&[ann], 800_000).await.unwrap();

        let round1 = repo.list_for_round("round-1").await.unwrap();
        assert_eq!(round1.len(), 1);
    }

    #[tokio::test]
    async fn list_for_round_unknown_returns_empty() {
        let repo = fresh_repo().await;
        assert!(repo.list_for_round("missing").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_after_height_orders_by_height_then_id() {
        let repo = fresh_repo().await;

        repo.insert_announcements(&[make_announcement("r-100", "v1:0", "pk1")], 100)
            .await
            .unwrap();
        repo.insert_announcements(&[make_announcement("r-200", "v2:0", "pk2")], 200)
            .await
            .unwrap();
        repo.insert_announcements(&[make_announcement("r-300", "v3:0", "pk3")], 300)
            .await
            .unwrap();

        // Strictly greater than the cutoff.
        let after_100 = repo.list_after_height(100, 100).await.unwrap();
        assert_eq!(after_100.len(), 2);
        assert_eq!(after_100[0].round_id, "r-200");
        assert_eq!(after_100[1].round_id, "r-300");

        // Limit is honoured.
        let after_50_limit_2 = repo.list_after_height(50, 2).await.unwrap();
        assert_eq!(after_50_limit_2.len(), 2);
        assert_eq!(after_50_limit_2[0].round_id, "r-100");
        assert_eq!(after_50_limit_2[1].round_id, "r-200");
    }

    #[tokio::test]
    async fn list_after_height_above_max_returns_empty() {
        let repo = fresh_repo().await;
        repo.insert_announcements(&[make_announcement("r1", "v1:0", "pk1")], 100)
            .await
            .unwrap();

        assert!(repo.list_after_height(100, 100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn prune_before_drops_only_below_cutoff_and_returns_count() {
        let repo = fresh_repo().await;

        repo.insert_announcements(&[make_announcement("r-100", "v1:0", "pk1")], 100)
            .await
            .unwrap();
        repo.insert_announcements(&[make_announcement("r-200", "v2:0", "pk2")], 200)
            .await
            .unwrap();
        repo.insert_announcements(&[make_announcement("r-300", "v3:0", "pk3")], 300)
            .await
            .unwrap();

        // Strictly less than: 200 stays, 100 is dropped.
        let pruned = repo.prune_before(200).await.unwrap();
        assert_eq!(pruned, 1);

        let remaining = repo.list_after_height(0, 100).await.unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].round_id, "r-200");
        assert_eq!(remaining[1].round_id, "r-300");
    }

    #[tokio::test]
    async fn prune_before_with_no_matches_is_a_no_op() {
        let repo = fresh_repo().await;
        repo.insert_announcements(&[make_announcement("r-100", "v1:0", "pk1")], 100)
            .await
            .unwrap();

        let pruned = repo.prune_before(50).await.unwrap();
        assert_eq!(pruned, 0);

        assert_eq!(repo.list_for_round("r-100").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn batch_insert_is_atomic() {
        // The batch insert opens a single transaction; verify all rows are
        // visible after commit (and that a successful batch leaves the
        // count consistent with the input length).
        let repo = fresh_repo().await;

        let batch: Vec<RoundAnnouncement> = (0..16)
            .map(|i| make_announcement("round-1", &format!("vtxo-{i}:0"), &format!("pk{i}")))
            .collect();
        repo.insert_announcements(&batch, 12_345).await.unwrap();

        let stored = repo.list_for_round("round-1").await.unwrap();
        assert_eq!(stored.len(), 16);
    }
}
