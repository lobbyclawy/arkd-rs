//! PSAR end-to-end pipeline parameterisation smoke test at K=10, N=4
//! (issue #676).
//!
//! Cheaper companion to `e2e_psar_n12.rs` — runs the same boarding +
//! per-epoch flow at a smaller cohort to catch parameterisation
//! regressions cheaply during routine `cargo test`.

#[path = "_psar_support.rs"]
mod support;

#[test]
fn psar_pipeline_k10_n4_in_process() {
    let (log, _elapsed) = support::run_pipeline(10, 4, 0xb0);
    assert_eq!(log.len(), 4);
    for (i, arts) in log.iter().enumerate() {
        assert_eq!(arts.epoch, (i + 1) as u32);
        assert_eq!(arts.signatures.len(), 10);
        assert!(arts.failures.is_empty());
    }
}
