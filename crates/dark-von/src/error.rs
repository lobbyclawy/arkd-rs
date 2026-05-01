//! Crate-level error types.
//!
//! Per `docs/conventions/errors.md`: per-module enums with structured
//! variants, `#[non_exhaustive]`, lowercase sentence-form messages.

use thiserror::Error;

/// Errors raised by the `ecvrf` module.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EcvrfError {
    #[error("malformed proof: expected {expected} bytes, got {got}")]
    MalformedProofLength { expected: usize, got: usize },

    #[error("malformed proof: gamma is not a valid secp256k1 point")]
    MalformedProofGamma,

    #[error("malformed proof: scalar `s` is not in `[0, n)`")]
    MalformedProofScalar,

    #[error("invalid public key: not a valid secp256k1 point")]
    InvalidPublicKey,

    #[error("verification failed: challenge mismatch")]
    VerificationFailed,

    #[error("hash-to-curve exhausted 256 counter values")]
    HashToCurveExhausted,

    #[error("scalar arithmetic produced zero (negligible probability under honest input)")]
    ScalarZero,

    #[error("secp256k1 backend error")]
    Backend(#[from] secp256k1::Error),
}
