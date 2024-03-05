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
    #[error("invalid bivariate polynomial")]
    InvalidBivariatePolynomial,
    #[error("invalid data")]
    InvalidData,
    #[error("round mismatch")]
    RoundMismatch,
    #[error("runtime mismatch")]
    RuntimeMismatch,
    #[error("status not published")]
    StatusNotPublished,
    #[error("zero threshold")]
    ZeroThreshold,
}
