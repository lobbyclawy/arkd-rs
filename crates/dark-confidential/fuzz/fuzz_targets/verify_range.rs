//! Fuzz target: feed arbitrary bytes into the range-proof verifier.
//!
//! Asserts no panic on malformed input. The verifier path must stay
//! robust against attacker-controlled bytes — a panic here would be a
//! denial-of-service against any node deserialising round payloads.
//!
//! Build with `cargo +nightly fuzz run verify_range` inside this crate.

#![no_main]

use libfuzzer_sys::fuzz_target;

use dark_confidential::range_proof::{verify_range, verify_range_aggregated, RangeProof, ValueCommitment};

fuzz_target!(|data: &[u8]| {
    if data.len() < 34 {
        return;
    }
    let commitment_bytes = &data[..33];
    let proof_bytes = &data[33..];

    // Parse both. If either fails, that is the correct handling — we are
    // only asserting no panics inside the verify path.
    let Ok(commitment) = ValueCommitment::from_bytes(commitment_bytes) else {
        return;
    };
    let Ok(proof) = RangeProof::from_bytes(proof_bytes) else {
        return;
    };

    // Single-verify and aggregated-verify accept opposite tags; both are
    // tolerated and return bool, never panic.
    let _ = verify_range(&commitment, &proof);
    let _ = verify_range_aggregated(std::slice::from_ref(&commitment), &proof);
});
