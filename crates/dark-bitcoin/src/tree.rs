//! MuSig2 key aggregation for Taproot VTXO trees.
//!
//! Implements BIP-327 MuSig2 key aggregation using the `musig2` crate,
//! replacing the previous SHA256-based placeholder. The aggregated key
//! is used as the Taproot internal key for cooperative spending paths.

use bitcoin::XOnlyPublicKey;

use crate::error::{BitcoinError, BitcoinResult};

/// Aggregate multiple compressed public keys into a single MuSig2 combined key.
///
/// This is the primary aggregation function that preserves the original parity
/// (02/03 prefix) of each input key. This is critical for protocol compatibility:
/// the Go SDK's btcd musig2 library performs full-point equality checks, so both
/// tree building and signing must use keys with identical serialization.
///
/// # Arguments
/// * `compressed_keys` - Slice of 33-byte compressed public keys (with 02/03 prefix).
///   Must contain at least 2 keys. Keys are sorted lexicographically before
///   aggregation to ensure deterministic output regardless of input order.
///
/// # Returns
/// The aggregated x-only public key (for use as Taproot internal key).
///
/// # Errors
/// Returns an error if fewer than 2 keys are provided, if any key is invalid,
/// or if key aggregation fails (e.g., keys sum to the point at infinity).
pub fn aggregate_keys_compressed(compressed_keys: &[[u8; 33]]) -> BitcoinResult<XOnlyPublicKey> {
    if compressed_keys.len() < 2 {
        return Err(BitcoinError::ScriptError(
            "MuSig2 key aggregation requires at least 2 public keys".to_string(),
        ));
    }

    // Parse compressed keys preserving original parity (02/03 prefix)
    let mut musig_pubkeys: Vec<musig2::secp256k1::PublicKey> = compressed_keys
        .iter()
        .map(|key| {
            musig2::secp256k1::PublicKey::from_slice(key).map_err(|e| {
                BitcoinError::ScriptError(format!("Invalid compressed public key for MuSig2: {}", e))
            })
        })
        .collect::<BitcoinResult<Vec<_>>>()?;

    // Sort for deterministic aggregation (BIP-327 recommends sorted keys)
    musig_pubkeys.sort();

    let key_agg_ctx = musig2::KeyAggContext::new(musig_pubkeys)
        .map_err(|e| BitcoinError::ScriptError(format!("MuSig2 key aggregation failed: {}", e)))?;

    // Get the aggregated public key as x-only (for Taproot)
    let agg_pubkey: musig2::secp256k1::XOnlyPublicKey = key_agg_ctx.aggregated_pubkey();

    // Convert back to bitcoin 0.32 XOnlyPublicKey via serialized bytes
    let agg_bytes = agg_pubkey.serialize();
    XOnlyPublicKey::from_slice(&agg_bytes)
        .map_err(|e| BitcoinError::ScriptError(format!("Invalid aggregated key: {}", e)))
}

/// Aggregate multiple x-only public keys into a single MuSig2 combined key.
///
/// **DEPRECATED**: This function converts x-only keys to compressed format by
/// always using 0x02 (even parity). For protocol compatibility with the Go SDK,
/// use [`aggregate_keys_compressed`] instead, which preserves the original parity.
///
/// # Arguments
/// * `pubkeys` - Slice of x-only public keys to aggregate. Must contain
///   at least 2 keys. Keys are sorted lexicographically before aggregation
///   to ensure deterministic output regardless of input order.
///
/// # Returns
/// The aggregated x-only public key.
///
/// # Errors
/// Returns an error if fewer than 2 keys are provided, or if key
/// aggregation fails (e.g., keys sum to the point at infinity).
#[deprecated(
    since = "0.1.0",
    note = "Use aggregate_keys_compressed to preserve original key parity for Go SDK compatibility"
)]
pub fn aggregate_keys(pubkeys: &[XOnlyPublicKey]) -> BitcoinResult<XOnlyPublicKey> {
    if pubkeys.len() < 2 {
        return Err(BitcoinError::ScriptError(
            "MuSig2 key aggregation requires at least 2 public keys".to_string(),
        ));
    }

    // Convert x-only to compressed with 0x02 prefix (even parity)
    let compressed: Vec<[u8; 33]> = pubkeys
        .iter()
        .map(|xonly| {
            let mut buf = [0u8; 33];
            buf[0] = 0x02;
            buf[1..].copy_from_slice(&xonly.serialize());
            buf
        })
        .collect();

    aggregate_keys_compressed(&compressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    /// Helper: generate a deterministic XOnlyPublicKey from a 32-byte secret.
    fn test_xonly_key(secret_bytes: [u8; 32]) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        XOnlyPublicKey::from(pk)
    }

    /// Helper: generate a deterministic compressed pubkey (33 bytes) from a 32-byte secret.
    fn test_compressed_key(secret_bytes: [u8; 32]) -> [u8; 33] {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        pk.serialize()
    }

    #[test]
    fn aggregate_compressed_two_keys_produces_valid_output() {
        let key1 = test_compressed_key([1u8; 32]);
        let key2 = test_compressed_key([2u8; 32]);

        let agg = aggregate_keys_compressed(&[key1, key2]).expect("should aggregate 2 keys");

        // Aggregated key should be 32 bytes (x-only)
        assert_eq!(agg.serialize().len(), 32);
    }

    #[test]
    fn aggregate_compressed_is_deterministic() {
        let key1 = test_compressed_key([1u8; 32]);
        let key2 = test_compressed_key([2u8; 32]);

        let agg_a = aggregate_keys_compressed(&[key1, key2]).unwrap();
        let agg_b = aggregate_keys_compressed(&[key1, key2]).unwrap();
        let agg_c = aggregate_keys_compressed(&[key2, key1]).unwrap();

        assert_eq!(agg_a, agg_b, "same order must be deterministic");
        assert_eq!(agg_a, agg_c, "reversed order must match (keys are sorted)");
    }

    #[test]
    fn aggregate_compressed_preserves_parity() {
        // Create keys with known even (02) and odd (03) parity
        let key_even = test_compressed_key([1u8; 32]);
        let key_odd = test_compressed_key([2u8; 32]);

        // Verify the keys have different parities (at least one should be 03)
        // This depends on the specific secret keys chosen
        let has_even = key_even[0] == 0x02 || key_odd[0] == 0x02;
        let has_odd = key_even[0] == 0x03 || key_odd[0] == 0x03;

        // The test is meaningful only if we have different parities
        // If both happen to be same parity, just ensure aggregation works
        let agg = aggregate_keys_compressed(&[key_even, key_odd]).unwrap();
        assert_eq!(agg.serialize().len(), 32);

        // If we have mixed parities, verify that flipping parity changes the result
        if has_even && has_odd {
            // Create version with flipped parity
            let mut key_even_flipped = key_even;
            key_even_flipped[0] = if key_even[0] == 0x02 { 0x03 } else { 0x02 };

            // This should produce a DIFFERENT aggregated key (or fail to parse)
            // because the MuSig2 coefficients depend on the full serialized form
            if let Ok(agg_flipped) =
                aggregate_keys_compressed(&[key_even_flipped, key_odd])
            {
                // If it parsed (some flipped keys are still valid points), the agg should differ
                // Actually, flipping 02<->03 gives a different y coordinate but same x,
                // which is still a valid curve point, so aggregation should succeed
                // but produce a different result
                assert_ne!(
                    agg, agg_flipped,
                    "Different key parities should produce different aggregated keys"
                );
            }
        }
    }

    #[test]
    fn aggregate_compressed_rejects_single_key() {
        let key = test_compressed_key([1u8; 32]);
        let err = aggregate_keys_compressed(&[key]).unwrap_err();
        assert!(
            err.to_string().contains("at least 2"),
            "error should mention minimum: {}",
            err
        );
    }

    #[test]
    fn aggregate_compressed_rejects_empty_keys() {
        let err = aggregate_keys_compressed(&[]).unwrap_err();
        assert!(err.to_string().contains("at least 2"));
    }

    // Legacy tests for deprecated aggregate_keys function
    #[allow(deprecated)]
    #[test]
    fn aggregate_two_keys_produces_valid_output() {
        let key1 = test_xonly_key([1u8; 32]);
        let key2 = test_xonly_key([2u8; 32]);

        let agg = aggregate_keys(&[key1, key2]).expect("should aggregate 2 keys");

        // Aggregated key must differ from both inputs
        assert_ne!(agg, key1);
        assert_ne!(agg, key2);
    }

    #[allow(deprecated)]
    #[test]
    fn aggregation_is_deterministic() {
        let key1 = test_xonly_key([1u8; 32]);
        let key2 = test_xonly_key([2u8; 32]);

        let agg_a = aggregate_keys(&[key1, key2]).unwrap();
        let agg_b = aggregate_keys(&[key1, key2]).unwrap();
        let agg_c = aggregate_keys(&[key2, key1]).unwrap();

        assert_eq!(agg_a, agg_b, "same order must be deterministic");
        assert_eq!(agg_a, agg_c, "reversed order must match (keys are sorted)");
    }

    #[allow(deprecated)]
    #[test]
    fn same_key_twice_is_valid() {
        let key = test_xonly_key([1u8; 32]);
        let result = aggregate_keys(&[key, key]);
        assert!(result.is_ok(), "MuSig2 allows duplicate keys");
    }

    #[allow(deprecated)]
    #[test]
    fn many_keys_aggregation() {
        let keys: Vec<XOnlyPublicKey> = (1u8..=10)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = i;
                test_xonly_key(bytes)
            })
            .collect();

        let agg = aggregate_keys(&keys).expect("should aggregate 10 keys");

        // Verify round-trip serialization
        let bytes = agg.serialize();
        assert_eq!(bytes.len(), 32);
        let reparsed = XOnlyPublicKey::from_slice(&bytes).unwrap();
        assert_eq!(agg, reparsed);
    }

    #[allow(deprecated)]
    #[test]
    fn rejects_single_key() {
        let key = test_xonly_key([1u8; 32]);
        let err = aggregate_keys(&[key]).unwrap_err();
        assert!(
            err.to_string().contains("at least 2"),
            "error should mention minimum: {}",
            err
        );
    }

    #[allow(deprecated)]
    #[test]
    fn rejects_empty_keys() {
        let err = aggregate_keys(&[]).unwrap_err();
        assert!(err.to_string().contains("at least 2"));
    }

    #[allow(deprecated)]
    #[test]
    fn aggregated_key_round_trips_as_xonly() {
        let key1 = test_xonly_key([3u8; 32]);
        let key2 = test_xonly_key([4u8; 32]);

        let agg = aggregate_keys(&[key1, key2]).unwrap();
        let bytes = agg.serialize();
        assert_eq!(bytes.len(), 32);
        assert_eq!(XOnlyPublicKey::from_slice(&bytes).unwrap(), agg);
    }
}
