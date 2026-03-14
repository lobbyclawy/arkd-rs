//! Local signer — loads ASP key from config and signs locally.

use async_trait::async_trait;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::XOnlyPublicKey;

use crate::error::ArkResult;
use crate::ports::SignerService;

/// A local signer that holds a secret key in memory.
///
/// Use [`LocalSigner::from_hex`] to load from a hex-encoded private key
/// (e.g. from config), or [`LocalSigner::random`] for dev/test.
pub struct LocalSigner {
    secret_key: SecretKey,
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl LocalSigner {
    /// Create a `LocalSigner` from a hex-encoded 32-byte secret key.
    pub fn from_hex(hex_key: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = hex::decode(hex_key)?;
        let secret_key = SecretKey::from_slice(&bytes)?;
        Ok(Self {
            secret_key,
            secp: Secp256k1::new(),
        })
    }

    /// Generate a random signer (useful for testing / dev mode).
    pub fn random() -> Self {
        use bitcoin::secp256k1::rand::rngs::OsRng;
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut OsRng);
        Self { secret_key, secp }
    }

    /// Return the compressed public key bytes (33 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        bitcoin::secp256k1::PublicKey::from_secret_key(&self.secp, &self.secret_key)
            .serialize()
            .to_vec()
    }
}

#[async_trait]
impl SignerService for LocalSigner {
    async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&self.secp, &self.secret_key);
        let (xonly, _parity) = pk.x_only_public_key();
        Ok(xonly)
    }

    async fn sign_transaction(&self, partial_tx: &str, _extract_raw: bool) -> ArkResult<String> {
        // TODO(#80): Implement real PSBT signing with the secret key.
        // For now, return the transaction as-is (matches MockSigner behaviour)
        // so the rest of the pipeline can be wired up.
        Ok(partial_tx.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1};

    #[tokio::test]
    async fn test_local_signer_random_generates_valid_pubkey() {
        let signer = LocalSigner::random();
        let pk = signer.get_pubkey().await.unwrap();
        // XOnlyPublicKey serialises to 32 bytes
        assert_eq!(pk.serialize().len(), 32);
    }

    #[tokio::test]
    async fn test_local_signer_from_hex_is_deterministic() {
        let hex_key = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
        let s1 = LocalSigner::from_hex(hex_key).unwrap();
        let s2 = LocalSigner::from_hex(hex_key).unwrap();
        assert_eq!(
            s1.get_pubkey().await.unwrap(),
            s2.get_pubkey().await.unwrap()
        );
    }

    #[test]
    fn test_local_signer_pubkey_is_33_bytes() {
        let signer = LocalSigner::random();
        assert_eq!(signer.public_key_bytes().len(), 33);
    }

    #[tokio::test]
    async fn test_local_signer_sign_produces_valid_signature() {
        let signer = LocalSigner::random();
        let secp = Secp256k1::new();

        // Create a message and sign it directly with the key to verify crypto works
        let msg = Message::from_digest([0xab; 32]);
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &signer.secret_key);
        let sig = secp.sign_schnorr(&msg, &keypair);

        let pubkey = signer.get_pubkey().await.unwrap();
        assert!(secp.verify_schnorr(&sig, &msg, &pubkey).is_ok());
    }

    #[tokio::test]
    async fn test_local_signer_sign_transaction_returns_input() {
        let signer = LocalSigner::random();
        let result = signer.sign_transaction("deadbeef", false).await.unwrap();
        assert_eq!(result, "deadbeef");
    }
}
