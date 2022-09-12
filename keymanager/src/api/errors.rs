use thiserror::Error;

/// Key manager error.
#[derive(Error, Debug)]
pub enum KeyManagerError {
    #[error("client session is not authenticated")]
    NotAuthenticated,
    #[error("client is not authorized")]
    NotAuthorized,
    #[error("invalid epoch")]
    InvalidEpoch,
    #[error("height is not fresh")]
    HeightNotFresh,
    #[error("key manager is not initialized")]
    NotInitialized,
    #[error("key manager state corrupted")]
    StateCorrupted,
    #[error("key manager replication required")]
    ReplicationRequired,
    #[error("policy rollback")]
    PolicyRollback,
    #[error("policy alteration, without serial increment")]
    PolicyChanged,
    #[error("policy has invalid runtime")]
    PolicyInvalidRuntime,
    #[error("policy is malformed or invalid: {0}")]
    PolicyInvalid(#[from] anyhow::Error),
    #[error("policy has insufficient signatures")]
    PolicyInsufficientSignatures,
    #[error("policy hasn't been published")]
    PolicyNotPublished,
    #[error(transparent)]
    Other(anyhow::Error),
}
