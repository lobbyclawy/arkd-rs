//! Pedersen commitment primitives for Confidential VTXOs.
//!
//! Threat model notes:
//! - Reusing a blinding factor across distinct amounts leaks the difference
//!   between commitments and weakens confidentiality.
//! - Commitment serialization is canonical compressed secp256k1 point encoding.
//! - The alternate generator `H` is deterministically derived from a domain-
//!   separated hash so no party can bias it after the fact.

use core::ops::{Add, Neg, Sub};
use secp256k1::{
    constants::GENERATOR_X,
    hashes::{sha256, Hash},
    PublicKey, Scalar, Secp256k1, SecretKey,
};

use crate::{ConfidentialError, Result};

const PEDERSEN_H_DST: &[u8] = b"dark-confidential/pedersen-h/v1";
const PEDERSEN_H_COMPRESSED: [u8; 33] = [
    0x02, 0xa6, 0x3d, 0x22, 0xdd, 0x8d, 0xaf, 0x89, 0x5f, 0xc6, 0x48, 0xa4, 0xdb, 0xaf, 0xc0, 0x2c,
    0xb0, 0x3f, 0xc6, 0xa7, 0xc9, 0x6d, 0x64, 0x2d, 0x0c, 0xc1, 0x86, 0xae, 0x56, 0x4c, 0x02, 0x1c,
    0xb4,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PedersenCommitment(PublicKey);

impl PedersenCommitment {
    pub fn commit(amount: u64, blinding: &Scalar) -> Result<Self> {
        let secp = Secp256k1::new();
        let amount_point = if amount == 0 {
            None
        } else {
            let amount_scalar = scalar_from_u64(amount)?;
            let amount_secret = secret_key_from_scalar(&amount_scalar)?;
            Some(PublicKey::from_secret_key(&secp, &amount_secret))
        };
        let h_point = pedersen_h();
        let blinded_h = h_point
            .mul_tweak(&secp, blinding)
            .map_err(|_| ConfidentialError::InvalidInput("invalid blinding tweak"))?;
        let combined = match amount_point {
            Some(amount_point) => amount_point
                .combine(&blinded_h)
                .map_err(|_| ConfidentialError::InvalidInput("invalid commitment sum"))?,
            None => blinded_h,
        };

        Ok(Self(combined))
    }

    pub fn add(&self, other: &Self) -> Result<Self> {
        self.0
            .combine(&other.0)
            .map(Self)
            .map_err(|_| ConfidentialError::InvalidInput("invalid commitment addition"))
    }

    pub fn sub(&self, other: &Self) -> Result<Self> {
        self.add(&other.negate())
    }

    pub fn negate(&self) -> Self {
        Self(self.0.negate(&Secp256k1::new()))
    }

    pub fn to_bytes(&self) -> [u8; 33] {
        self.0.serialize()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let pk = PublicKey::from_slice(bytes).map_err(|_| {
            ConfidentialError::InvalidEncoding("invalid compressed secp256k1 point")
        })?;
        Ok(Self(pk))
    }
}

impl Add for PedersenCommitment {
    type Output = Result<Self>;

    fn add(self, rhs: Self) -> Self::Output {
        PedersenCommitment::add(&self, &rhs)
    }
}

impl Sub for PedersenCommitment {
    type Output = Result<Self>;

    fn sub(self, rhs: Self) -> Self::Output {
        PedersenCommitment::sub(&self, &rhs)
    }
}

impl Neg for PedersenCommitment {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.negate()
    }
}

pub fn pedersen_h() -> PublicKey {
    PublicKey::from_slice(&PEDERSEN_H_COMPRESSED).expect("hard-coded Pedersen H must be valid")
}

pub fn pedersen_h_seed() -> [u8; 32] {
    let mut data = Vec::with_capacity(PEDERSEN_H_DST.len() + 1 + GENERATOR_X.len() + 4);
    data.extend_from_slice(PEDERSEN_H_DST);
    data.push(0x00);
    data.extend_from_slice(&GENERATOR_X);
    data.extend_from_slice(&0u32.to_be_bytes());
    sha256::Hash::hash(&data).to_byte_array()
}

fn scalar_from_u64(value: u64) -> Result<Scalar> {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_be_bytes(bytes)
        .map_err(|_| ConfidentialError::InvalidInput("amount scalar overflow"))
}

fn secret_key_from_scalar(scalar: &Scalar) -> Result<SecretKey> {
    SecretKey::from_slice(&scalar.to_be_bytes()).map_err(|_| {
        ConfidentialError::InvalidInput("scalar must be non-zero and within curve order")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::{prelude::any, prop_assert_eq, prop_assume};
    use serde::Deserialize;
    use std::fs;

    #[derive(Debug, Deserialize)]
    struct GeneratorVectors {
        generator_derivation: GeneratorDerivation,
    }

    #[derive(Debug, Deserialize)]
    struct GeneratorDerivation {
        domain_separator: String,
        seed_hex: String,
        compressed_hex: String,
    }

    #[test]
    fn serialization_round_trip() {
        let blinding = Scalar::from_be_bytes([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .unwrap();
        let commitment = PedersenCommitment::commit(42, &blinding).unwrap();
        let bytes = commitment.to_bytes();
        let decoded = PedersenCommitment::from_bytes(&bytes).unwrap();
        assert_eq!(commitment, decoded);
    }

    #[test]
    fn known_answer_generator_vector_matches() {
        let content = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/pedersen.json"
        ))
        .unwrap();
        let vectors: GeneratorVectors = serde_json::from_str(&content).unwrap();
        assert_eq!(
            vectors.generator_derivation.domain_separator,
            String::from_utf8(PEDERSEN_H_DST.to_vec()).unwrap()
        );
        assert_eq!(
            hex::encode(pedersen_h_seed()),
            vectors.generator_derivation.seed_hex
        );
        assert_eq!(
            hex::encode(pedersen_h().serialize()),
            vectors.generator_derivation.compressed_hex
        );
    }

    proptest::proptest! {
        #[test]
        fn homomorphic_property_holds(a in any::<u64>(), b in any::<u64>(), r1 in 1u64..u64::MAX, r2 in 1u64..u64::MAX) {
            prop_assume!(a.checked_add(b).is_some());
            let r1 = scalar_from_u64(r1).unwrap();
            let r2 = scalar_from_u64(r2).unwrap();
            let mut bytes = r1.to_be_bytes();
            let mut carry = 0u16;
            for (dst, src) in bytes.iter_mut().rev().zip(r2.to_be_bytes().iter().rev()) {
                let sum = *dst as u16 + *src as u16 + carry;
                *dst = (sum & 0xff) as u8;
                carry = sum >> 8;
            }
            prop_assume!(carry == 0);
            let rsum = Scalar::from_be_bytes(bytes).unwrap();

            let lhs = PedersenCommitment::commit(a + b, &rsum).unwrap();
            let lhs_a = PedersenCommitment::commit(a, &r1).unwrap();
            let lhs_b = PedersenCommitment::commit(b, &r2).unwrap();
            let rhs = PedersenCommitment::add(&lhs_a, &lhs_b).unwrap();
            prop_assert_eq!(lhs, rhs);
        }
    }
}
