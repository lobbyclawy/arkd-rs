//! Public adapter: VON-driven partial signing on top of BIP-327.

use secp256k1::{PublicKey, SecretKey};

use crate::bip327::key_agg::{key_agg, KeyAggCtx};
use crate::bip327::sign::{aggregate_and_finalize, partial_sign_with_scalars, point_from_scalar};
use crate::error::{Bip327Error, VonMusig2Error};
use crate::nonces::{AggNonce, PubNonce};

/// 32-byte partial-signature scalar (wire-compatible with `musig2 = "0.3.1"`'s
/// `PartialSignature::to_bytes()`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartialSignature(pub [u8; 32]);

impl PartialSignature {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, Bip327Error> {
        if bytes.len() != 32 {
            return Err(Bip327Error::MalformedPartialSignature);
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(bytes);
        // Validate s ∈ [0, n).
        let _ = secp256k1::Scalar::from_be_bytes(s)
            .map_err(|_| Bip327Error::PartialSignatureOutOfRange)?;
        Ok(PartialSignature(s))
    }
}

/// Build a [`PubNonce`] from VON's `(R₁, R₂)` public points.
///
/// VON returns `R = r·G` per scalar; for MuSig2 the operator publishes
/// `(R₁, R₂)`. This helper exists only for API symmetry — it's a struct
/// constructor.
pub fn pub_nonces_from_von(r1: PublicKey, r2: PublicKey) -> PubNonce {
    PubNonce { r1, r2 }
}

/// Re-export of the BIP-327 key aggregation. Public so callers can construct
/// the context they pass to [`sign_partial_with_von`].
pub fn build_key_agg_ctx(pubkeys: &[PublicKey]) -> Result<KeyAggCtx, Bip327Error> {
    key_agg(pubkeys)
}

/// Operator's partial-signature step.
///
/// `(k₁, k₂)` are the operator's VON-retained scalars (from
/// `dark_von::wrapper::nonce`'s `r` value across the `b ∈ {1, 2}` slots),
/// passed in as `SecretKey`. The function does **not** generate or hash a
/// nonce internally — VON's binding is preserved end-to-end.
///
/// `agg_nonce` is the BIP-327 aggregated nonce across all signers (operator
/// included); the participant side typically computes it via
/// [`AggNonce::sum`] or by feeding everyone's [`PubNonce`] through
/// `musig2 = "0.3.1"`'s `AggNonce::sum`.
pub fn sign_partial_with_von(
    ctx: &KeyAggCtx,
    operator_sk: &SecretKey,
    von_scalars: (&SecretKey, &SecretKey),
    agg_nonce: &AggNonce,
    msg: &[u8; 32],
) -> Result<PartialSignature, VonMusig2Error> {
    // Sanity: operator's pubkey must be in the key-agg set.
    let op_pk = point_from_scalar(operator_sk);
    if !ctx.pubkeys.contains(&op_pk) {
        return Err(VonMusig2Error::OperatorNotInKeyAgg);
    }
    let s = partial_sign_with_scalars(
        ctx,
        operator_sk,
        von_scalars.0,
        von_scalars.1,
        agg_nonce,
        msg,
    )?;
    Ok(PartialSignature(s))
}

/// Aggregate operator + participant partial sigs into a final BIP-340 64-byte signature.
pub fn aggregate(
    ctx: &KeyAggCtx,
    agg_nonce: &AggNonce,
    msg: &[u8; 32],
    partials: &[PartialSignature],
) -> Result<[u8; 64], Bip327Error> {
    let raw: Vec<[u8; 32]> = partials.iter().map(|p| p.0).collect();
    aggregate_and_finalize(agg_nonce, ctx, msg, &raw)
}
