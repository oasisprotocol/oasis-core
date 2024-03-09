//! Lagrange interpolation.

mod multiplier;
mod naive;
mod optimized;

// Re-exports.
pub use self::{naive::*, optimized::*};
