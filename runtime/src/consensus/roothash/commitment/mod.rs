//! Roothash commitments.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/roothash/api/commitment.
//!
use std::any::Any;

use crate::common::crypto::hash::Hash;

// Modules.
mod executor;
mod pool;

// Re-exports.
pub use executor::*;
pub use pool::*;

/// Verified roothash commitment.
pub trait OpenCommitment {
    /// Returns true if the commitment is mostly equal to another
    /// specified commitment as per discrepancy detection criteria.
    ///
    /// The caller MUST guarantee that the passed commitment is of the same
    /// type.
    fn mostly_equal(&self, other: &Self) -> bool
    where
        Self: Sized;

    /// Returns true if this commitment indicates a failure.
    fn is_indicating_failure(&self) -> bool;

    /// Returns a hash that represents a vote for this commitment as
    /// per discrepancy resolution criteria.
    fn to_vote(&self) -> Hash;

    /// Returns a commitment-specific result after discrepancy
    /// detection.
    fn to_dd_result(&self) -> &dyn Any;
}
