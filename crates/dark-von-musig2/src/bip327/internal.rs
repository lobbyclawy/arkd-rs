//! Crate-internal helpers used by the bip327 module.

use std::sync::OnceLock;

use secp256k1::{constants::CURVE_ORDER, PublicKey, Scalar, Secp256k1, SecretKey};

pub(crate) fn secp() -> &'static Secp256k1<secp256k1::All> {
    static S: OnceLock<Secp256k1<secp256k1::All>> = OnceLock::new();
    S.get_or_init(Secp256k1::new)
}

pub(crate) fn generator() -> &'static PublicKey {
    static G: OnceLock<PublicKey> = OnceLock::new();
    G.get_or_init(|| {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let one = SecretKey::from_slice(&bytes).expect("1 is a valid secret key");
        PublicKey::from_secret_key(secp(), &one)
    })
}

/// Reduce a 32-byte big-endian value mod `n` (curve order).
///
/// Same algorithm as `dark_von::internal::bits2octets_mod_q`: for SHA-256 output
/// (256 bits) and `n ≈ 2^256`, at most one subtraction suffices.
pub(crate) fn reduce_mod_n(input: &[u8; 32]) -> [u8; 32] {
    if Scalar::from_be_bytes(*input).is_ok() {
        *input
    } else {
        sub_n(input)
    }
}

fn sub_n(input: &[u8; 32]) -> [u8; 32] {
    let q = CURVE_ORDER;
    let mut result = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = i16::from(input[i]) - i16::from(q[i]) - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }
    result
}

/// Convert a `SecretKey` (always non-zero scalar in `[1, n)`) to `Scalar`.
pub(crate) fn scalar_of(sk: &SecretKey) -> Scalar {
    Scalar::from_be_bytes(sk.secret_bytes()).expect("SecretKey bytes are always a valid scalar")
}

/// Negate a scalar mod `n`. Input must be in `[0, n)`.
pub(crate) fn neg_mod_n(scalar: &[u8; 32]) -> [u8; 32] {
    if scalar == &[0u8; 32] {
        return *scalar;
    }
    // n - scalar
    let q = CURVE_ORDER;
    let mut result = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = i16::from(q[i]) - i16::from(scalar[i]) - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }
    debug_assert_eq!(borrow, 0, "scalar < n by precondition");
    result
}

/// `true` iff the public key has even y-coordinate (BIP-340 sense).
pub(crate) fn has_even_y(pk: &PublicKey) -> bool {
    // Compressed encoding: first byte is 0x02 (even Y) or 0x03 (odd Y).
    pk.serialize()[0] == 0x02
}
