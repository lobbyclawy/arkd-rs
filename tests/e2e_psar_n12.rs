//! PSAR end-to-end pipeline at K=100, N=12 (issue #676).
//!
//! Boards the cohort via `asp_board`, advances through all 12 epochs
//! via `process_epoch`, and asserts every emitted BIP-340 signature
//! verifies against the cohort's 2-of-2 aggregated Taproot key.
//! Runs in-process — no Nigiri or regtest dependency. The acceptance
//! budget per the issue is 5 minutes on dev hardware; this test
//! typically completes in under 30 seconds.

#[path = "_psar_support.rs"]
mod support;

#[test]
fn psar_pipeline_k100_n12_in_process() {
    let (log, elapsed) = support::run_pipeline(100, 12, 0xa0);
    assert_eq!(log.len(), 12);
    for (i, arts) in log.iter().enumerate() {
        assert_eq!(arts.epoch, (i + 1) as u32);
        assert_eq!(arts.signatures.len(), 100);
        assert!(arts.failures.is_empty());
    }
    assert!(
        elapsed.as_secs() < 5 * 60,
        "K=100 N=12 acceptance budget breach: {elapsed:?}"
    );
}
