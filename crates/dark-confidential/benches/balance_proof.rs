//! Criterion benchmarks for balance-proof prove/verify.
//!
//! Representative shape: 2 inputs, 2 outputs, nonzero fee. Regression
//! thresholds are tracked externally (CI workflow), not asserted here.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dark_confidential::balance_proof::{prove_balance, verify_balance, BalanceProof};
use dark_confidential::commitment::PedersenCommitment;
use secp256k1::Scalar;

fn scalar(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes).unwrap()
}

struct Fixture {
    input_blindings: [Scalar; 2],
    output_blindings: [Scalar; 2],
    inputs: [PedersenCommitment; 2],
    outputs: [PedersenCommitment; 2],
    fee: u64,
    tx_hash: [u8; 32],
    proof: BalanceProof,
}

fn fixture() -> Fixture {
    let input_blindings = [scalar(0x1111_1111), scalar(0x2222_2222)];
    let output_blindings = [scalar(0x3333_3333), scalar(0x4444_4444)];
    let fee: u64 = 10;
    let tx_hash = [0x5au8; 32];
    let inputs = [
        PedersenCommitment::commit(100, &input_blindings[0]).unwrap(),
        PedersenCommitment::commit(50, &input_blindings[1]).unwrap(),
    ];
    let outputs = [
        PedersenCommitment::commit(120, &output_blindings[0]).unwrap(),
        PedersenCommitment::commit(20, &output_blindings[1]).unwrap(),
    ];
    let proof = prove_balance(&input_blindings, &output_blindings, fee, &tx_hash).unwrap();
    Fixture {
        input_blindings,
        output_blindings,
        inputs,
        outputs,
        fee,
        tx_hash,
        proof,
    }
}

fn balance_proof_benchmark(c: &mut Criterion) {
    let f = fixture();

    let mut group = c.benchmark_group("balance_proof");
    group.bench_function("prove", |b| {
        b.iter(|| {
            let _ = prove_balance(
                black_box(&f.input_blindings),
                black_box(&f.output_blindings),
                black_box(f.fee),
                black_box(&f.tx_hash),
            )
            .unwrap();
        });
    });
    group.bench_function("verify", |b| {
        b.iter(|| {
            assert!(verify_balance(
                black_box(&f.inputs),
                black_box(&f.outputs),
                black_box(f.fee),
                black_box(&f.tx_hash),
                black_box(&f.proof),
            ))
        });
    });
    group.finish();
}

criterion_group!(benches, balance_proof_benchmark);
criterion_main!(benches);
