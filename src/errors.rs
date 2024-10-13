use plonky2::hash::hash_types::RichField;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CircuitError {
    #[error("Invalid recursion depth: {0}")]
    InvalidRecursionDepth(usize),

    #[error("Failed to convert slice to HashOutTarget: {0}")]
    ConversionError(String),

    #[error("Hash verification failed: {0}")]
    HashVerificationFailed(String),

    #[error("Other error occurred: {0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum HashChainError<F: RichField> {
    #[error("Invalid recursion depth: {0}. Expected at least 1")]
    InvalidRecursionDepth(usize),

    #[error("Hash verification failed. Expected: {expected:?}, Got: {actual:?}")]
    HashVerificationFailed { expected: Vec<F>, actual: Vec<F> },

    #[error("Other error occurred: {0}")]
    Other(String),
}
