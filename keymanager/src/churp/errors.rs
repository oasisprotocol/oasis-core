//! CHURP errors.

/// CHURP error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("application submitted")]
    ApplicationsSubmitted,
    #[error("applications closed")]
    ApplicationsClosed,
    #[error("bivariate polynomial decoding failed")]
    BivariatePolynomialDecodingFailed,
    #[error("dealer mismatch")]
    DealerMismatch,
    #[error("handoffs disabled")]
    HandoffsDisabled,
    #[error("handoff mismatch")]
    HandoffMismatch,
    #[error("invalid bivariate polynomial")]
    InvalidBivariatePolynomial,
    #[error("invalid data")]
    InvalidData,
    #[error("invalid secret share")]
    InvalidSecretShare,
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
