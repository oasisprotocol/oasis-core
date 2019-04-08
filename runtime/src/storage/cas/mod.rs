//! Content-addressable storage.
use std::sync::Arc;

use failure::Fallible;

use crate::common::crypto::hash::Hash;

pub mod memory;
pub mod passthrough;

/// Content-addressable storage.
pub trait CAS: Send + Sync {
    /// Fetch the value for a specific immutable key.
    fn get(&self, key: Hash) -> Fallible<Vec<u8>>;

    /// Store a specific value into storage. It can be later retrieved by its hash.
    /// Expiry represents a number of Epochs for which the value should remain available.
    fn insert(&self, value: Vec<u8>, expiry: u64) -> Fallible<Hash>;
}

impl<T: ?Sized + CAS> CAS for Arc<T> {
    fn get(&self, key: Hash) -> Fallible<Vec<u8>> {
        CAS::get(&**self, key)
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> Fallible<Hash> {
        CAS::insert(&**self, value, expiry)
    }
}

// Re-exports.
pub use self::{memory::MemoryCAS, passthrough::PassthroughCAS};
