use thiserror::Error;

use oasis_core_runtime::consensus::{state::StateError, verifier};

/// Key manager error.
#[derive(Error, Debug)]
pub enum KeyManagerError {
    #[error("client session is not authenticated")]
    NotAuthenticated,
    #[error("client is not authorized")]
    NotAuthorized,
    #[error("invalid epoch: expected {0}, got {1}")]
    InvalidEpoch(u64, u64),
    #[error("invalid generation: expected {0}, got {1}")]
    InvalidGeneration(u64, u64),
    #[error("generation is in the future: expected max {0}, got {1}")]
    GenerationFromFuture(u64, u64),
    #[error("height is not fresh")]
    HeightNotFresh,
    #[error("key manager is not initialized")]
    NotInitialized,
    #[error("key manager state corrupted")]
    StateCorrupted,
    #[error("key manager storage corrupted")]
    StorageCorrupted,
    #[error("policy required")]
    PolicyRequired,
    #[error("policy rollback")]
    PolicyRollback,
    #[error("policy alteration, without serial increment")]
    PolicyChanged,
    #[error("policy has invalid runtime")]
    PolicyInvalidRuntime,
    #[error("insufficient key shares")]
    InsufficientKeyShares,
    #[error("insufficient signatures")]
    InsufficientSignatures,
    #[error("runtime signing key missing")]
    RSKMissing,
    #[error("runtime encryption key not published")]
    REKNotPublished,
    #[error("signature verification failed: {0}")]
    InvalidSignature(#[source] anyhow::Error),
    #[error("master secret checksum mismatch")]
    MasterSecretChecksumMismatch,
    #[error("master secret generation {0} not found")]
    MasterSecretNotFound(u64),
    #[error("master secret generation {0} not replicated")]
    MasterSecretNotReplicated(u64),
    #[error("master secret not published")]
    MasterSecretNotPublished,
    #[error("ephemeral secret for epoch {0} not found")]
    EphemeralSecretNotFound(u64),
    #[error("ephemeral secret for epoch {0} not replicated")]
    EphemeralSecretNotReplicated(u64),
    #[error("ephemeral secret not published")]
    EphemeralSecretNotPublished,
    #[error("ephemeral secret checksum mismatch")]
    EphemeralSecretChecksumMismatch,
    #[error("invalid ciphertext")]
    InvalidCiphertext,
    #[error("status not found")]
    StatusNotFound,
    #[error("runtime mismatch")]
    RuntimeMismatch,
    #[error("active deployment not found")]
    ActiveDeploymentNotFound,
    #[error("state error: {0}")]
    StateError(#[from] StateError),
    #[error("verification error: {0}")]
    VerificationError(#[from] verifier::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
