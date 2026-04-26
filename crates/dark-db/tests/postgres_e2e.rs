//! PostgreSQL end-to-end integration test
//!
//! Requires a running PostgreSQL instance. Set `DATABASE_URL` to run:
//! ```bash
//! DATABASE_URL=postgres://user:pass@localhost/dark_test cargo test --features postgres -p dark-db --test postgres_e2e
//! ```
//! The test is silently skipped when `DATABASE_URL` is not set, so CI
//! won't fail on machines without a Postgres instance.

#![cfg(feature = "postgres")]

use dark_core::domain::{Round, RoundStage, Stage};
use dark_core::ports::{RoundAnnouncement, RoundAnnouncementRepository, RoundRepository};
use dark_db::{
    create_postgres_pool, run_postgres_migrations, PgRoundAnnouncementRepository, PgRoundRepository,
};

/// Full round-trip: connect → migrate → insert round → read back → verify.
#[tokio::test]
async fn postgres_round_trip() {
    // Skip when no DATABASE_URL is provided (CI without Postgres).
    let db_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("DATABASE_URL not set — skipping PostgreSQL E2E test");
            return;
        }
    };

    // 1. Connect
    let pool = create_postgres_pool(&db_url)
        .await
        .expect("Failed to create PostgreSQL pool");

    // 2. Run migrations
    run_postgres_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    // 3. Build a test round
    let mut round = Round::new();
    round.starting_timestamp = 1_700_000_000;
    round.ending_timestamp = 1_700_003_600;
    round.stage = Stage {
        code: RoundStage::Finalization,
        ended: true,
        failed: false,
        entered_at: None,
    };
    round.commitment_txid = "e2e_commit_txid".to_string();
    round.commitment_tx = "e2e_commit_tx_hex".to_string();
    round.connector_address = "tb1qtest".to_string();
    round.version = 1;
    round.swept = false;
    round.vtxo_tree_expiration = 1_700_100_000;

    let round_id = round.id.clone();

    // 4. Persist via PgRoundRepository
    let repo = PgRoundRepository::new(pool.clone());
    repo.add_or_update_round(&round)
        .await
        .expect("Failed to insert round");

    // 5. Read back and verify
    let fetched = repo
        .get_round_with_id(&round_id)
        .await
        .expect("Failed to fetch round")
        .expect("Round should exist");

    assert_eq!(fetched.id, round_id);
    assert_eq!(fetched.starting_timestamp, 1_700_000_000);
    assert_eq!(fetched.ending_timestamp, 1_700_003_600);
    assert_eq!(fetched.stage.code, RoundStage::Finalization);
    assert!(fetched.stage.ended);
    assert!(!fetched.stage.failed);
    assert_eq!(fetched.commitment_txid, "e2e_commit_txid");
    assert_eq!(fetched.commitment_tx, "e2e_commit_tx_hex");
    assert_eq!(fetched.connector_address, "tb1qtest");
    assert_eq!(fetched.version, 1);
    assert!(!fetched.swept);
    assert_eq!(fetched.vtxo_tree_expiration, 1_700_100_000);

    // 6. Clean up: remove the test round so the test is idempotent
    sqlx::query("DELETE FROM rounds WHERE id = $1")
        .bind(&round_id)
        .execute(&pool)
        .await
        .expect("Failed to clean up test round");
}

/// Full round-trip for the round announcement repo (issue #556).
///
/// Inserts a small batch, reads back via every query method, prunes a
/// cutoff, and verifies the row counts at each step. Cleans up its own
/// rows so the test is idempotent.
#[tokio::test]
async fn postgres_round_announcement_round_trip() {
    let db_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("DATABASE_URL not set — skipping PostgreSQL E2E test");
            return;
        }
    };

    let pool = create_postgres_pool(&db_url)
        .await
        .expect("Failed to create PostgreSQL pool");
    run_postgres_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    // Use a unique round-id prefix so concurrent runs do not collide.
    let test_prefix = format!("e2e-ann-{}", uuid::Uuid::new_v4());
    let round_low = format!("{test_prefix}-low");
    let round_mid = format!("{test_prefix}-mid");
    let round_high = format!("{test_prefix}-high");

    let repo = PgRoundAnnouncementRepository::new(pool.clone());

    let make = |round_id: &str, vtxo_id: &str, pk: &str| RoundAnnouncement {
        round_id: round_id.to_string(),
        vtxo_id: vtxo_id.to_string(),
        ephemeral_pubkey: pk.to_string(),
    };

    // Insert three rounds at different block heights.
    repo.insert_announcements(
        &[
            make(&round_low, "vtxo-b:0", "pk_b"),
            make(&round_low, "vtxo-a:0", "pk_a"),
        ],
        100,
    )
    .await
    .expect("insert low");
    repo.insert_announcements(&[make(&round_mid, "vtxo-c:0", "pk_c")], 200)
        .await
        .expect("insert mid");
    repo.insert_announcements(&[make(&round_high, "vtxo-d:0", "pk_d")], 300)
        .await
        .expect("insert high");

    // list_for_round returns rows ordered by vtxo_id.
    let low_rows = repo.list_for_round(&round_low).await.expect("list low");
    assert_eq!(low_rows.len(), 2);
    assert_eq!(low_rows[0].vtxo_id, "vtxo-a:0");
    assert_eq!(low_rows[1].vtxo_id, "vtxo-b:0");

    // list_after_height returns strictly greater rows ordered by height.
    let after_100: Vec<_> = repo
        .list_after_height(100, 100)
        .await
        .expect("list after height")
        .into_iter()
        .filter(|r| r.round_id.starts_with(&test_prefix))
        .collect();
    assert_eq!(after_100.len(), 2);
    assert_eq!(after_100[0].round_id, round_mid);
    assert_eq!(after_100[1].round_id, round_high);

    // Idempotent insert: replaying the same row does not duplicate it.
    repo.insert_announcements(&[make(&round_low, "vtxo-a:0", "pk_a")], 100)
        .await
        .expect("idempotent insert");
    assert_eq!(
        repo.list_for_round(&round_low)
            .await
            .expect("re-list low")
            .len(),
        2
    );

    // prune_before drops only rows strictly below the cutoff and reports
    // the count.
    let pruned = repo.prune_before(200).await.expect("prune");
    assert!(pruned >= 2, "should prune at least the two low rows");

    let after_prune: Vec<_> = repo
        .list_after_height(0, 100)
        .await
        .expect("list after prune")
        .into_iter()
        .filter(|r| r.round_id.starts_with(&test_prefix))
        .collect();
    assert_eq!(after_prune.len(), 2);
    assert!(after_prune.iter().any(|r| r.round_id == round_mid));
    assert!(after_prune.iter().any(|r| r.round_id == round_high));

    // Clean up everything we inserted.
    sqlx::query("DELETE FROM round_announcements WHERE round_id LIKE $1")
        .bind(format!("{test_prefix}%"))
        .execute(&pool)
        .await
        .expect("Failed to clean up test announcements");
}
