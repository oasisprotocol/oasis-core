//! CHURP errors.

/// CHURP error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("application submitted")]
    ApplicationsSubmitted,
    #[error("applications closed")]
    ApplicationsClosed,
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
    #[error("policy rollback")]
    PolicyRollback,
    #[error("runtime mismatch")]
    RuntimeMismatch,
    #[error("status not published")]
    StatusNotPublished,
}
