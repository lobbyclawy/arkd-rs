//! Confidential memo encryption helpers for selective disclosure.
//!
//! This module implements ADR-0003's v1 memo wire format. The encrypted memo is
//! a fixed-width 134-byte blob:
//!
//! `version (1) || ephemeral_pk (33) || nonce (12) || ciphertext+tag (88)`
//!
//! The plaintext is also fixed width:
//!
//! `amount_le_u64 (8) || blinding (32) || one_time_spend_tag (32)`
//!
//! The sender derives the AEAD key material from ECDH(`ephemeral_sk`,
//! `scan_pk`), expands it with HKDF-SHA256 using `ephemeral_pk` as salt, and
//! then encrypts under ChaCha20-Poly1305 with AAD
//! `version || ephemeral_pk || one_time_pk`.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{ConfidentialError, Result};

pub const MEMO_VERSION_V1: u8 = 0x01;
pub const MEMO_WIRE_LEN: usize = 134;
pub const MEMO_PLAINTEXT_LEN: usize = 72;
pub const MEMO_AEAD_KEY_LEN: usize = 32;
pub const MEMO_NONCE_LEN: usize = 12;
pub const MEMO_EPHEMERAL_PK_LEN: usize = 33;
pub const MEMO_ONE_TIME_PK_LEN: usize = 33;
const MEMO_CIPHERTEXT_AND_TAG_LEN: usize = 88;
const MEMO_HKDF_INFO: &[u8] = b"dark-confidential/memo/v1";

/// Decoded plaintext carried inside a confidential memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialMemoPlaintext {
    pub amount: u64,
    pub blinding: [u8; 32],
    pub one_time_spend_tag: [u8; 32],
}

impl ConfidentialMemoPlaintext {
    pub fn encode(&self) -> [u8; MEMO_PLAINTEXT_LEN] {
        let mut out = [0u8; MEMO_PLAINTEXT_LEN];
        out[..8].copy_from_slice(&self.amount.to_le_bytes());
        out[8..40].copy_from_slice(&self.blinding);
        out[40..72].copy_from_slice(&self.one_time_spend_tag);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MEMO_PLAINTEXT_LEN {
            return Err(ConfidentialError::InvalidEncoding(
                "memo plaintext must be 72 bytes",
            ));
        }

        let mut amount_bytes = [0u8; 8];
        amount_bytes.copy_from_slice(&bytes[..8]);
        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&bytes[8..40]);
        let mut one_time_spend_tag = [0u8; 32];
        one_time_spend_tag.copy_from_slice(&bytes[40..72]);

        Ok(Self {
            amount: u64::from_le_bytes(amount_bytes),
            blinding,
            one_time_spend_tag,
        })
    }
}

/// Parsed memo wire object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialMemo {
    pub version: u8,
    pub ephemeral_pk: [u8; MEMO_EPHEMERAL_PK_LEN],
    pub nonce: [u8; MEMO_NONCE_LEN],
    pub ciphertext_and_tag: [u8; MEMO_CIPHERTEXT_AND_TAG_LEN],
}

impl ConfidentialMemo {
    pub fn to_bytes(&self) -> [u8; MEMO_WIRE_LEN] {
        let mut out = [0u8; MEMO_WIRE_LEN];
        out[0] = self.version;
        out[1..34].copy_from_slice(&self.ephemeral_pk);
        out[34..46].copy_from_slice(&self.nonce);
        out[46..134].copy_from_slice(&self.ciphertext_and_tag);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MEMO_WIRE_LEN {
            return Err(ConfidentialError::InvalidEncoding(
                "memo wire must be 134 bytes",
            ));
        }
        if bytes[0] != MEMO_VERSION_V1 {
            return Err(ConfidentialError::InvalidEncoding("unknown version"));
        }

        let mut ephemeral_pk = [0u8; MEMO_EPHEMERAL_PK_LEN];
        ephemeral_pk.copy_from_slice(&bytes[1..34]);
        PublicKey::from_slice(&ephemeral_pk)
            .map_err(|_| ConfidentialError::InvalidEncoding("invalid ephemeral public key"))?;

        let mut nonce = [0u8; MEMO_NONCE_LEN];
        nonce.copy_from_slice(&bytes[34..46]);
        let mut ciphertext_and_tag = [0u8; MEMO_CIPHERTEXT_AND_TAG_LEN];
        ciphertext_and_tag.copy_from_slice(&bytes[46..134]);

        Ok(Self {
            version: bytes[0],
            ephemeral_pk,
            nonce,
            ciphertext_and_tag,
        })
    }
}

/// Encrypt a v1 confidential memo using ADR-0003's deterministic KDF/AAD.
pub fn encrypt_memo(
    scan_pk: &PublicKey,
    one_time_pk: &[u8; MEMO_ONE_TIME_PK_LEN],
    ephemeral_sk: &SecretKey,
    plaintext: &ConfidentialMemoPlaintext,
) -> Result<ConfidentialMemo> {
    let secp = Secp256k1::new();
    let ephemeral_pk = PublicKey::from_secret_key(&secp, ephemeral_sk).serialize();
    let (aead_key, nonce) = derive_key_material(scan_pk, ephemeral_sk, &ephemeral_pk)?;
    let aad = build_aad(&ephemeral_pk, one_time_pk);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let mut encoded = plaintext.encode();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &encoded,
                aad: &aad,
            },
        )
        .map_err(|_| ConfidentialError::InvalidInput("aead encryption failed"))?;
    encoded.zeroize();

    let ciphertext_and_tag: [u8; MEMO_CIPHERTEXT_AND_TAG_LEN] = ciphertext
        .try_into()
        .map_err(|_| ConfidentialError::InvalidEncoding("aead output length mismatch"))?;

    Ok(ConfidentialMemo {
        version: MEMO_VERSION_V1,
        ephemeral_pk,
        nonce,
        ciphertext_and_tag,
    })
}

/// Decrypt a v1 confidential memo and recover its fixed-width plaintext.
pub fn decrypt_memo(
    scan_sk: &SecretKey,
    one_time_pk: &[u8; MEMO_ONE_TIME_PK_LEN],
    memo_wire: &[u8],
) -> Result<ConfidentialMemoPlaintext> {
    let memo = ConfidentialMemo::from_bytes(memo_wire)?;
    let ephemeral_pk = PublicKey::from_slice(&memo.ephemeral_pk)
        .map_err(|_| ConfidentialError::InvalidEncoding("invalid ephemeral public key"))?;
    let (aead_key, nonce) = derive_key_material(&ephemeral_pk, scan_sk, &memo.ephemeral_pk)?;
    let aad = build_aad(&memo.ephemeral_pk, one_time_pk);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let mut plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &memo.ciphertext_and_tag,
                aad: &aad,
            },
        )
        .map_err(|_| ConfidentialError::InvalidInput("aead tag"))?;

    if memo.nonce != nonce {
        plaintext.zeroize();
        return Err(ConfidentialError::InvalidInput("aead tag"));
    }

    let decoded = ConfidentialMemoPlaintext::decode(&plaintext);
    plaintext.zeroize();
    decoded
}

fn derive_key_material(
    peer_pk: &PublicKey,
    scalar_sk: &SecretKey,
    salt_ephemeral_pk: &[u8; MEMO_EPHEMERAL_PK_LEN],
) -> Result<([u8; MEMO_AEAD_KEY_LEN], [u8; MEMO_NONCE_LEN])> {
    let secp = Secp256k1::new();
    let scalar = Scalar::from_be_bytes(scalar_sk.secret_bytes())
        .map_err(|_| ConfidentialError::InvalidInput("invalid scalar secret key"))?;
    let shared_point = (*peer_pk)
        .mul_tweak(&secp, &scalar)
        .map_err(|_| ConfidentialError::InvalidInput("invalid ecdh point"))?
        .serialize();

    let hk = Hkdf::<Sha256>::new(Some(salt_ephemeral_pk), &shared_point);
    let mut okm = [0u8; MEMO_AEAD_KEY_LEN + MEMO_NONCE_LEN];
    hk.expand(MEMO_HKDF_INFO, &mut okm)
        .map_err(|_| ConfidentialError::InvalidInput("hkdf output length invalid"))?;

    let mut key = [0u8; MEMO_AEAD_KEY_LEN];
    key.copy_from_slice(&okm[..MEMO_AEAD_KEY_LEN]);
    let mut nonce = [0u8; MEMO_NONCE_LEN];
    nonce.copy_from_slice(&okm[MEMO_AEAD_KEY_LEN..]);
    okm.zeroize();

    Ok((key, nonce))
}

fn build_aad(
    ephemeral_pk: &[u8; MEMO_EPHEMERAL_PK_LEN],
    one_time_pk: &[u8; MEMO_ONE_TIME_PK_LEN],
) -> [u8; 67] {
    let mut aad = [0u8; 67];
    aad[0] = MEMO_VERSION_V1;
    aad[1..34].copy_from_slice(ephemeral_pk);
    aad[34..67].copy_from_slice(one_time_pk);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn hex33(hex: &str) -> [u8; 33] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    #[test]
    fn plaintext_round_trip() {
        let plaintext = ConfidentialMemoPlaintext {
            amount: 42,
            blinding: [0x11; 32],
            one_time_spend_tag: [0x22; 32],
        };
        assert_eq!(
            ConfidentialMemoPlaintext::decode(&plaintext.encode()).unwrap(),
            plaintext
        );
    }

    #[test]
    fn vector_a_encrypt_and_decrypt_match() {
        let scan_pk = PublicKey::from_slice(&hex33(
            "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486",
        ))
        .unwrap();
        let one_time_pk =
            hex33("03187db77a59f1c5f3cfd2296f87ebd7e829226b0f628d9efe4b9f221414e3b967");
        let ephemeral_sk = SecretKey::from_slice(&hex32(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ))
        .unwrap();
        let scan_sk = SecretKey::from_slice(&hex32(
            "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
        ))
        .unwrap();
        let plaintext = ConfidentialMemoPlaintext {
            amount: 21_000_000,
            blinding: [0x11; 32],
            one_time_spend_tag: [0x22; 32],
        };

        let memo = encrypt_memo(&scan_pk, &one_time_pk, &ephemeral_sk, &plaintext).unwrap();
        assert_eq!(
            hex::encode(memo.to_bytes()),
            "01036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2863137b3b4329ab0b9b1ef00019ded27e89f4a3d7f64d0a7e56ba0ea827f15a2ec8091bdfe9159de52f47bf8ff3a936bdacca386464fe70f439c130b4606be924c60126eb8d1a9d264c6ebc5cc28362649a5153b0291d04ea09b69cf95f2b8b1a86d1a57"
        );

        let decrypted = decrypt_memo(&scan_sk, &one_time_pk, &memo.to_bytes()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn vector_b_zero_amount_matches() {
        let scan_pk = PublicKey::from_slice(&hex33(
            "0268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b5",
        ))
        .unwrap();
        let one_time_pk =
            hex33("02b95c249d84f417e3e395a127425428b540671cc15881eb828c17b722a53fc599");
        let ephemeral_sk = SecretKey::from_slice(&hex32(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ))
        .unwrap();
        let scan_sk = SecretKey::from_slice(&hex32(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ))
        .unwrap();
        let plaintext = ConfidentialMemoPlaintext {
            amount: 0,
            blinding: [0u8; 32],
            one_time_spend_tag: [0x33; 32],
        };

        let memo = encrypt_memo(&scan_pk, &one_time_pk, &ephemeral_sk, &plaintext).unwrap();
        assert_eq!(
            hex::encode(memo.to_bytes()),
            "01026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3189f4064c7a97bffa93d052cc8075d23370c23e51e178256b748f4f43913a92af2f1a1fe8b4fe58aeaf0ac1e72800f0b08125bbe5711b8c9ab8897175254a6acdde7210932802bc9e5e2b49218963f8a51159fa661cb2ec9d3cdc525dfbbb58c4f8f288d"
        );
        assert_eq!(
            decrypt_memo(&scan_sk, &one_time_pk, &memo.to_bytes()).unwrap(),
            plaintext
        );
    }

    #[test]
    fn vector_c_max_amount_matches() {
        let scan_pk = PublicKey::from_slice(&hex33(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        ))
        .unwrap();
        let one_time_pk =
            hex33("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
        let ephemeral_sk = SecretKey::from_slice(&hex32(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ))
        .unwrap();
        let scan_sk = SecretKey::from_slice(&hex32(
            "0000000000000000000000000000000000000000000000000000000000000002",
        ))
        .unwrap();
        let plaintext = ConfidentialMemoPlaintext {
            amount: u64::MAX,
            blinding: [0xff; 32],
            one_time_spend_tag: [0x44; 32],
        };

        let memo = encrypt_memo(&scan_pk, &one_time_pk, &ephemeral_sk, &plaintext).unwrap();
        assert_eq!(
            hex::encode(memo.to_bytes()),
            "010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798973e4e8fb4f4b299cc16c1434f0279c8ff26087f0227ff8fd84426a8cbdbcff47e64443b707161628a36c64a869816669ad55f712e3f65746284800106a12dd107d8904b20cb92acd82181bce2a0aad858de74c2309a1823771ca0b20986d6270fb355e9"
        );
        assert_eq!(
            decrypt_memo(&scan_sk, &one_time_pk, &memo.to_bytes()).unwrap(),
            plaintext
        );
    }

    #[test]
    fn decrypt_rejects_wrong_recipient() {
        let one_time_pk =
            hex33("03187db77a59f1c5f3cfd2296f87ebd7e829226b0f628d9efe4b9f221414e3b967");
        let wrong_scan_sk = SecretKey::from_slice(&hex32(
            "0000000000000000000000000000000000000000000000000000000000000099",
        ))
        .unwrap();
        let memo = hex::decode("01036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2863137b3b4329ab0b9b1ef00019ded27e89f4a3d7f64d0a7e56ba0ea827f15a2ec8091bdfe9159de52f47bf8ff3a936bdacca386464fe70f439c130b4606be924c60126eb8d1a9d264c6ebc5cc28362649a5153b0291d04ea09b69cf95f2b8b1a86d1a57").unwrap();
        assert_eq!(
            decrypt_memo(&wrong_scan_sk, &one_time_pk, &memo)
                .unwrap_err()
                .to_string(),
            "invalid input: aead tag"
        );
    }

    #[test]
    fn decrypt_rejects_aad_graft() {
        let scan_sk = SecretKey::from_slice(&hex32(
            "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
        ))
        .unwrap();
        let mut wrong_one_time_pk =
            hex33("03187db77a59f1c5f3cfd2296f87ebd7e829226b0f628d9efe4b9f221414e3b967");
        wrong_one_time_pk[1] ^= 0x01;
        let memo = hex::decode("01036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2863137b3b4329ab0b9b1ef00019ded27e89f4a3d7f64d0a7e56ba0ea827f15a2ec8091bdfe9159de52f47bf8ff3a936bdacca386464fe70f439c130b4606be924c60126eb8d1a9d264c6ebc5cc28362649a5153b0291d04ea09b69cf95f2b8b1a86d1a57").unwrap();
        assert_eq!(
            decrypt_memo(&scan_sk, &wrong_one_time_pk, &memo)
                .unwrap_err()
                .to_string(),
            "invalid input: aead tag"
        );
    }

    #[test]
    fn parser_rejects_unknown_version() {
        let mut memo = hex::decode("01036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2863137b3b4329ab0b9b1ef00019ded27e89f4a3d7f64d0a7e56ba0ea827f15a2ec8091bdfe9159de52f47bf8ff3a936bdacca386464fe70f439c130b4606be924c60126eb8d1a9d264c6ebc5cc28362649a5153b0291d04ea09b69cf95f2b8b1a86d1a57").unwrap();
        memo[0] = 0x02;
        assert_eq!(
            ConfidentialMemo::from_bytes(&memo).unwrap_err().to_string(),
            "invalid encoding: unknown version"
        );
    }

    #[test]
    fn decrypt_rejects_tampered_tag() {
        let scan_sk = SecretKey::from_slice(&hex32(
            "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
        ))
        .unwrap();
        let one_time_pk =
            hex33("03187db77a59f1c5f3cfd2296f87ebd7e829226b0f628d9efe4b9f221414e3b967");
        let mut memo = hex::decode("01036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2863137b3b4329ab0b9b1ef00019ded27e89f4a3d7f64d0a7e56ba0ea827f15a2ec8091bdfe9159de52f47bf8ff3a936bdacca386464fe70f439c130b4606be924c60126eb8d1a9d264c6ebc5cc28362649a5153b0291d04ea09b69cf95f2b8b1a86d1a57").unwrap();
        *memo.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            decrypt_memo(&scan_sk, &one_time_pk, &memo)
                .unwrap_err()
                .to_string(),
            "invalid input: aead tag"
        );
    }
}
