//! Polynomials for verifiable secret sharing.

mod bivariate;
mod univariate;

// Re-exports.
pub use self::{bivariate::*, univariate::*};
