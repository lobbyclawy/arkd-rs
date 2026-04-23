use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dark_confidential::commitment::PedersenCommitment;
use secp256k1::Scalar;

fn scalar(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes).unwrap()
}

fn pedersen_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("pedersen_commitment");
    let left = PedersenCommitment::commit(21, &scalar(1)).unwrap();
    let right = PedersenCommitment::commit(34, &scalar(2)).unwrap();

    group.bench_function("commit", |b| {
        b.iter(|| PedersenCommitment::commit(black_box(42), black_box(&scalar(1))).unwrap())
    });
    group.bench_function("add", |b| b.iter(|| left.add(black_box(&right)).unwrap()));
    group.bench_function("serialize", |b| b.iter(|| black_box(left.to_bytes())));
    group.finish();
}

criterion_group!(benches, pedersen_benchmark);
criterion_main!(benches);
