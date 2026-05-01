//! Public-nonce wire types.
//!
//! `PubNonce` and `AggNonce` are 66-byte wire blobs (`R₁_compressed || R₂_compressed`)
//! matching BIP-327 §"Public nonce encoding". Compatible with `musig2 = "0.3.1"`'s
//! `PubNonce::to_bytes()` / `AggNonce::to_bytes()` byte layout.

use secp256k1::PublicKey;

use crate::error::Bip327Error;

/// One signer's public-nonce contribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubNonce {
    pub r1: PublicKey,
    pub r2: PublicKey,
}

impl PubNonce {
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut out = [0u8; 66];
        out[..33].copy_from_slice(&self.r1.serialize());
        out[33..].copy_from_slice(&self.r2.serialize());
        out
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, Bip327Error> {
        if bytes.len() != 66 {
            return Err(Bip327Error::MalformedPubNonce);
        }
        let r1 = PublicKey::from_slice(&bytes[..33]).map_err(|_| Bip327Error::MalformedPubNonce)?;
        let r2 = PublicKey::from_slice(&bytes[33..]).map_err(|_| Bip327Error::MalformedPubNonce)?;
        Ok(PubNonce { r1, r2 })
    }
}

/// Aggregated public nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggNonce {
    pub r1: PublicKey,
    pub r2: PublicKey,
}

impl AggNonce {
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut out = [0u8; 66];
        out[..33].copy_from_slice(&self.r1.serialize());
        out[33..].copy_from_slice(&self.r2.serialize());
        out
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, Bip327Error> {
        if bytes.len() != 66 {
            return Err(Bip327Error::MalformedAggNonce);
        }
        let r1 = PublicKey::from_slice(&bytes[..33]).map_err(|_| Bip327Error::MalformedAggNonce)?;
        let r2 = PublicKey::from_slice(&bytes[33..]).map_err(|_| Bip327Error::MalformedAggNonce)?;
        Ok(AggNonce { r1, r2 })
    }

    /// Sum a set of [`PubNonce`] contributions per BIP-327 §"Nonce Aggregation".
    pub fn sum(pub_nonces: &[PubNonce]) -> Result<Self, Bip327Error> {
        if pub_nonces.is_empty() {
            return Err(Bip327Error::MalformedPubNonce);
        }
        let mut r1 = pub_nonces[0].r1;
        let mut r2 = pub_nonces[0].r2;
        for n in &pub_nonces[1..] {
            r1 = r1
                .combine(&n.r1)
                .map_err(|_| Bip327Error::AggregateInfinity)?;
            r2 = r2
                .combine(&n.r2)
                .map_err(|_| Bip327Error::AggregateInfinity)?;
        }
        Ok(AggNonce { r1, r2 })
    }
}
