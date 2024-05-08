//! CHURP errors.

/// CHURP error.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("application not submitted")]
    ApplicationNotSubmitted,
    #[error("application submitted")]
    ApplicationSubmitted,
    #[error("applications closed")]
    ApplicationsClosed,
    #[error("bivariate polynomial decoding failed")]
    BivariatePolynomialDecodingFailed,
    #[error("dealer mismatch")]
    DealerMismatch,
    #[error("dealer not found")]
    DealerNotFound,
    #[error("handoff closed")]
    HandoffClosed,
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
    #[error("invalid shareholder")]
    InvalidShareholder,
    #[error("invalid verification matrix checksum")]
    InvalidVerificationMatrixChecksum,
    #[error("not authenticated")]
    NotAuthenticated,
    #[error("not authorized")]
    NotAuthorized,
    #[error("not in committee")]
    NotInCommittee,
    #[error("point decoding failed")]
    PointDecodingFailed,
    #[error("policy rollback")]
    PolicyRollback,
    #[error("polynomial decoding failed")]
    PolynomialDecodingFailed,
    #[error("runtime mismatch")]
    RuntimeMismatch,
    #[error("shareholder mismatch")]
    ShareholderMismatch,
    #[error("shareholder not found")]
    ShareholderNotFound,
    #[error("status not published")]
    StatusNotPublished,
    #[error("verification matrix decoding failed")]
    VerificationMatrixDecodingFailed,
}
