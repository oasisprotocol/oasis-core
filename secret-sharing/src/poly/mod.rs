//! This package provides comprehensive tools for working with polynomials.
//!
//! Features include:
//!
//! - Univariate and bivariate polynomials
//! - Evaluation of points on polynomials
//! - Lagrange interpolation methods

mod arith;
mod bivariate;
pub mod lagrange;
mod point;
mod scalar;
mod univariate;

// Re-exports.
pub use self::{arith::*, bivariate::*, point::*, scalar::*, univariate::*};
