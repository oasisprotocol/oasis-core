//! CHURP errors.

/// CHURP error.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("application submitted")]
    ApplicationsSubmitted,
    #[error("applications closed")]
    ApplicationsClosed,
    #[error("bivariate polynomial decoding failed")]
    BivariatePolynomialDecodingFailed,
    #[error("dealer mismatch")]
    DealerMismatch,
    #[error("dealer not found")]
    DealerNotFound,
    #[error("handoffs disabled")]
    HandoffsDisabled,
    #[error("handoff downcast failed")]
    HandoffDowncastFailed,
    #[error("handoff mismatch")]
    HandoffMismatch,
    #[error("handoff not found")]
    HandoffNotFound,
    #[error("invalid bivariate polynomial")]
    InvalidBivariatePolynomial,
    #[error("invalid data")]
    InvalidData,
    #[error("invalid handoff")]
    InvalidHandoff,
    #[error("invalid secret share")]
    InvalidSecretShare,
    #[error("player mismatch")]
    PlayerMismatch,
    #[error("player not found")]
    PlayerNotFound,
    #[error("policy rollback")]
    PolicyRollback,
    #[error("runtime mismatch")]
    RuntimeMismatch,
    #[error("status not published")]
    StatusNotPublished,
    #[error("polynomial decoding failed")]
    PolynomialDecodingFailed,
    #[error("verification matrix decoding failed")]
    VerificationMatrixDecodingFailed,
}
