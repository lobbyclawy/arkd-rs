//! Round announcement repository — PostgreSQL implementation of
//! `dark_core::ports::RoundAnnouncementRepository` (issue #556).
//!
//! Mirrors the SQLite implementation. See `round_announcement_repo.rs` for
//! the schema rationale and the per-method contract.

use async_trait::async_trait;
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::{RoundAnnouncement, RoundAnnouncementRepository};
use sqlx::PgPool;
use tracing::debug;

/// PostgreSQL-backed announcement repository.
pub struct PgRoundAnnouncementRepository {
    pool: PgPool,
}

impl PgRoundAnnouncementRepository {
    /// Wrap an existing pool. The caller owns migration execution.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoundAnnouncementRepository for PgRoundAnnouncementRepository {
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
            block_height, "Inserting round announcements (PG)"
        );

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
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (round_id, vtxo_id) DO UPDATE SET
                    ephemeral_pubkey = EXCLUDED.ephemeral_pubkey,
                    block_height = EXCLUDED.block_height
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
        debug!(round_id, "Listing round announcements for round (PG)");

        let rows = sqlx::query_as::<_, AnnouncementRow>(
            r#"
            SELECT round_id, vtxo_id, ephemeral_pubkey
            FROM round_announcements
            WHERE round_id = $1
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
        debug!(
            height,
            limit, "Listing round announcements after height (PG)"
        );

        let rows = sqlx::query_as::<_, AnnouncementRow>(
            r#"
            SELECT round_id, vtxo_id, ephemeral_pubkey
            FROM round_announcements
            WHERE block_height > $1
            ORDER BY block_height ASC, round_id ASC, vtxo_id ASC
            LIMIT $2
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
        debug!(
            cutoff_block,
            "Pruning round announcements before cutoff (PG)"
        );

        let result = sqlx::query("DELETE FROM round_announcements WHERE block_height < $1")
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
