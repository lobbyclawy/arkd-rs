//! BIP-327 §"Key Aggregation".

use secp256k1::{PublicKey, Scalar};

use crate::error::Bip327Error;

use super::internal::{has_even_y, reduce_mod_n, secp};
use super::tagged::{tagged, KEYAGG_COEFF_TAG, KEYAGG_LIST_TAG};

/// Aggregated key produced by [`key_agg`].
#[derive(Clone, Debug)]
pub struct KeyAggCtx {
    /// Plain pubkeys in the order passed to [`key_agg`] (33-byte compressed).
    pub pubkeys: Vec<PublicKey>,
    /// `L = HashKeys(pk_1 || ... || pk_u)` per BIP-327.
    pub l: [u8; 32],
    /// "Second key" per BIP-327: the first `pk_j ≠ pk_1` (`j ≥ 2`), all-zero
    /// 33-byte sentinel if no such key exists.
    pub second_key_serialized: [u8; 33],
    /// Aggregated point `Q = Σ a_i · X_i`.
    pub q: PublicKey,
}

impl KeyAggCtx {
    /// Aggregated public key in 33-byte compressed form.
    pub fn aggregated_pubkey(&self) -> [u8; 33] {
        self.q.serialize()
    }

    /// Aggregated public key in 32-byte BIP-340 x-only form.
    pub fn x_only_pubkey(&self) -> [u8; 32] {
        let mut x = [0u8; 32];
        x.copy_from_slice(&self.q.serialize()[1..]);
        x
    }

    /// `true` iff `Q` has even y; mirrors BIP-340's parity convention.
    pub fn q_has_even_y(&self) -> bool {
        has_even_y(&self.q)
    }
}

/// `KeyAgg(pk_1..pk_u)` per BIP-327. Order-sensitive — does not sort.
pub fn key_agg(pubkeys: &[PublicKey]) -> Result<KeyAggCtx, Bip327Error> {
    if pubkeys.is_empty() {
        return Err(Bip327Error::EmptyPubkeySet);
    }
    let l = hash_keys(pubkeys);
    let second_key_serialized = get_second_key(pubkeys);
    let secp = secp();

    // Q = Σ a_i · X_i
    let mut q: Option<PublicKey> = None;
    for pk in pubkeys {
        let a = key_agg_coeff_internal(pk, &second_key_serialized, &l)?;
        let term = pk
            .mul_tweak(secp, &a)
            .map_err(|_| Bip327Error::ScalarZero)?;
        q = Some(match q {
            None => term,
            Some(acc) => acc
                .combine(&term)
                .map_err(|_| Bip327Error::InfiniteAggregateKey)?,
        });
    }

    Ok(KeyAggCtx {
        pubkeys: pubkeys.to_vec(),
        l,
        second_key_serialized,
        q: q.expect("at least one pubkey processed"),
    })
}

/// Return the key-agg coefficient `a_i` for the `pubkey` against this context's pubkey set.
pub fn key_agg_coeff(ctx: &KeyAggCtx, pubkey: &PublicKey) -> Result<Scalar, Bip327Error> {
    key_agg_coeff_internal(pubkey, &ctx.second_key_serialized, &ctx.l)
}

fn key_agg_coeff_internal(
    pk: &PublicKey,
    second_key_serialized: &[u8; 33],
    l: &[u8; 32],
) -> Result<Scalar, Bip327Error> {
    if pk.serialize() == *second_key_serialized {
        // Special case: a_2 = 1.
        let mut one = [0u8; 32];
        one[31] = 1;
        return Ok(Scalar::from_be_bytes(one).expect("1 is a valid scalar"));
    }
    let digest = tagged(
        &KEYAGG_COEFF_TAG,
        &[l.as_slice(), pk.serialize().as_slice()],
    );
    let reduced = reduce_mod_n(&digest);
    Scalar::from_be_bytes(reduced).map_err(|_| Bip327Error::ScalarZero)
}

fn hash_keys(pubkeys: &[PublicKey]) -> [u8; 32] {
    let mut parts: Vec<[u8; 33]> = Vec::with_capacity(pubkeys.len());
    for pk in pubkeys {
        parts.push(pk.serialize());
    }
    let part_refs: Vec<&[u8]> = parts.iter().map(|a| a.as_slice()).collect();
    tagged(&KEYAGG_LIST_TAG, &part_refs)
}

fn get_second_key(pubkeys: &[PublicKey]) -> [u8; 33] {
    let pk1 = pubkeys[0].serialize();
    for pk in &pubkeys[1..] {
        let s = pk.serialize();
        if s != pk1 {
            return s;
        }
    }
    [0u8; 33]
}
