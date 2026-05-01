//! Conformance vectors for `dark_von::ecvrf`.
//!
//! Per ADR-0006 (`docs/adr/0006-ecvrf-dependency-strategy.md`), RFC 9381 §A
//! contains *no* secp256k1 vectors. This suite is the project-pinned
//! substitute: 16 self-consistency vectors covering small/large secret-key
//! Hamming weight, near-bound scalars (1, n-1), and varied `alpha` lengths
//! (0, 1, 32, 33, 64, 100 bytes). The vectors are stored as JSON under
//! `tests/data/dark_vrf_secp256k1_tai.json` and the conformance test
//! recomputes `(beta, pi)` for each `(sk, alpha)` pair and asserts the
//! pinned bytes match.
//!
//! If a refactor of `ecvrf.rs` changes any output byte, the conformance
//! test fails loudly with the offending vector index. Regenerating the
//! file is intentional: run
//!
//! ```bash
//! cargo test -p dark-von --test ecvrf_rfc9381_vectors -- \
//!     emit_vectors --ignored --nocapture
//! ```
//!
//! and review the diff before committing.

use std::fs;
use std::path::PathBuf;

use dark_von::ecvrf::{prove, verify, Proof, PROOF_LEN, SUITE_STRING};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

const VECTOR_PATH: &str = "tests/data/dark_vrf_secp256k1_tai.json";

/// Inputs covering boundary conditions per ADR-0006:
/// low/high Hamming weight, near-bound scalars (1, n-1), and varied
/// alpha lengths.
const INPUTS: &[(&str, &str)] = &[
    // sk_hex, alpha_hex
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "00",
    ),
    (
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        "",
    ),
    (
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        "deadbeef",
    ),
    (
        "4242424242424242424242424242424242424242424242424242424242424242",
        "",
    ),
    (
        "4242424242424242424242424242424242424242424242424242424242424242",
        "61",
    ),
    (
        "4242424242424242424242424242424242424242424242424242424242424242",
        "0102030405060708090a0b0c0d0e0f10",
    ),
    (
        "4242424242424242424242424242424242424242424242424242424242424242",
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    ),
    (
        "4242424242424242424242424242424242424242424242424242424242424242",
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
    ),
    (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "",
    ),
    (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "53657475702d6964",
    ),
    (
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "",
    ),
    (
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "0000000000000000",
    ),
    (
        "5555555555555555555555555555555555555555555555555555555555555555",
        "ff",
    ),
    (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ff00ff00",
    ),
    (
        "1111111111111111111111111111111111111111111111111111111111111111",
        "44415641524b2d564f4e2d54455354",
    ),
];

#[derive(Debug, Serialize, Deserialize)]
struct VectorFile {
    suite_string: String,
    proof_len: usize,
    vectors: Vec<Vector>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Vector {
    index: usize,
    sk: String,
    alpha: String,
    pk: String,
    gamma: String,
    c: String,
    s: String,
    beta: String,
    proof: String,
}

#[test]
fn vectors_round_trip() {
    let path = vectors_path();
    let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "missing test-vector file {} ({}). Regenerate with `cargo test -p dark-von \
             --test ecvrf_rfc9381_vectors -- emit_vectors --ignored --nocapture`.",
            path.display(),
            err
        )
    });
    let file: VectorFile = serde_json::from_str(&raw).expect("vector JSON parses");

    assert_eq!(
        file.suite_string.as_bytes(),
        SUITE_STRING,
        "suite_string drift between vector file and crate constant"
    );
    assert_eq!(file.proof_len, PROOF_LEN, "PROOF_LEN drift");
    assert_eq!(file.vectors.len(), INPUTS.len(), "vector count mismatch");

    let secp = Secp256k1::new();
    for (i, (vec, (sk_hex, alpha_hex))) in file.vectors.iter().zip(INPUTS.iter()).enumerate() {
        assert_eq!(vec.index, i, "vector index drift");
        assert_eq!(vec.sk, *sk_hex);
        assert_eq!(vec.alpha, *alpha_hex);

        let sk_bytes: [u8; 32] = decode_array(sk_hex);
        let alpha = hex::decode(alpha_hex).unwrap();
        let sk = SecretKey::from_slice(&sk_bytes).expect("sk in (0, n)");
        let pk = PublicKey::from_secret_key(&secp, &sk);
        assert_eq!(hex::encode(pk.serialize()), vec.pk, "vector {i}: pk drift");

        let (beta, pi) = prove(&sk, &alpha).expect("prove ok");
        assert_eq!(hex::encode(beta), vec.beta, "vector {i}: beta drift");
        assert_eq!(
            hex::encode(pi.gamma().serialize()),
            vec.gamma,
            "vector {i}: gamma drift"
        );
        assert_eq!(hex::encode(pi.c()), vec.c, "vector {i}: c drift");
        assert_eq!(hex::encode(pi.s()), vec.s, "vector {i}: s drift");
        assert_eq!(
            hex::encode(pi.to_bytes()),
            vec.proof,
            "vector {i}: proof bytes drift"
        );

        let pi_round = Proof::from_slice(&pi.to_bytes()).expect("round-trip parse");
        assert_eq!(pi, pi_round);

        verify(&pk, &alpha, &beta, &pi).expect("vector {i}: verify ok");

        // Negative: mutating alpha must reject.
        if !alpha.is_empty() {
            let mut alpha_bad = alpha.clone();
            alpha_bad[0] ^= 0x01;
            verify(&pk, &alpha_bad, &beta, &pi).expect_err("mutated alpha must reject");
        }
        // Negative: mutating beta must reject.
        let mut beta_bad = beta;
        beta_bad[0] ^= 0x01;
        verify(&pk, &alpha, &beta_bad, &pi).expect_err("mutated beta must reject");
    }
}

#[test]
#[ignore = "regenerator; run with `--ignored` to refresh tests/data/dark_vrf_secp256k1_tai.json"]
fn emit_vectors() {
    let secp = Secp256k1::new();
    let mut vectors = Vec::with_capacity(INPUTS.len());
    for (i, (sk_hex, alpha_hex)) in INPUTS.iter().enumerate() {
        let sk_bytes: [u8; 32] = decode_array(sk_hex);
        let sk = SecretKey::from_slice(&sk_bytes).expect("sk in (0, n)");
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let alpha = hex::decode(alpha_hex).unwrap();
        let (beta, pi) = prove(&sk, &alpha).expect("prove ok");
        vectors.push(Vector {
            index: i,
            sk: (*sk_hex).to_string(),
            alpha: (*alpha_hex).to_string(),
            pk: hex::encode(pk.serialize()),
            gamma: hex::encode(pi.gamma().serialize()),
            c: hex::encode(pi.c()),
            s: hex::encode(pi.s()),
            beta: hex::encode(beta),
            proof: hex::encode(pi.to_bytes()),
        });
    }

    let file = VectorFile {
        suite_string: String::from_utf8(SUITE_STRING.to_vec()).expect("ascii"),
        proof_len: PROOF_LEN,
        vectors,
    };
    let json = serde_json::to_string_pretty(&file).expect("json");
    let path = vectors_path();
    fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
    fs::write(&path, json).expect("write");
    println!("wrote {} vectors to {}", INPUTS.len(), path.display());
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTOR_PATH)
}

fn decode_array(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("valid hex");
    bytes.try_into().expect("32 bytes")
}
