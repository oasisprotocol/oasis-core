//! Runtime storage interfaces and implementations.
use std::sync::Arc;

use crate::types::Error;

pub mod mkvs;

// Re-exports.
pub use self::mkvs::MKVS;

/// Trivial Key/Value storage.
pub trait KeyValue: Send + Sync {
    /// Fetch the value for a specific key.
    fn get(&self, key: Vec<u8>) -> Result<Vec<u8>, Error>;

    /// Store a specific key/value into storage.
    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error>;
}

impl<T: ?Sized + KeyValue> KeyValue for Arc<T> {
    fn get(&self, key: Vec<u8>) -> Result<Vec<u8>, Error> {
        KeyValue::get(&**self, key)
    }

    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error> {
        KeyValue::insert(&**self, key, value)
    }
}
