//! Runtime storage interfaces and implementations.
use std::sync::Arc;

use anyhow::Result;

pub mod context;
pub mod mkvs;

// Re-exports.
pub use self::{context::StorageContext, mkvs::MKVS};

/// Trivial Key/Value storage.
pub trait KeyValue: Send + Sync {
    /// Fetch the value for a specific key.
    fn get(&self, key: Vec<u8>) -> Result<Vec<u8>>;

    /// Store a specific key/value into storage.
    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()>;
}

impl<T: ?Sized + KeyValue> KeyValue for Arc<T> {
    fn get(&self, key: Vec<u8>) -> Result<Vec<u8>> {
        KeyValue::get(&**self, key)
    }

    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        KeyValue::insert(&**self, key, value)
    }
}
