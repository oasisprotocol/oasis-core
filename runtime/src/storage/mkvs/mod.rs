//! Merklized key-value store.
use failure::Fallible;

use crate::common::crypto::hash::Hash;

pub mod cas_patricia_trie;
pub mod urkel;

/// Merklized key-value store.
pub trait MKVS: Send + Sync {
    /// Fetch entry with given key.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Update entry with given key.
    ///
    /// If the database did not have this key present, [`None`] is returned.
    ///
    /// If the database did have this key present, the value is updated, and the old value is
    /// returned.
    ///
    /// [`None`]: std::option::Option
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>>;

    /// Remove entry with given key, returning the value at the key if the key was previously
    /// in the database.
    fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>>;

    /// Commit all database changes to the underlying store.
    fn commit(&mut self) -> Fallible<Hash>;

    /// Rollback any pending changes.
    fn rollback(&mut self);

    /// Set encryption key.
    fn set_encryption_key(&mut self, key: Option<&[u8]>);
}

/// Run specified closure with encryption key set, discard key afterwards.
///
/// # Examples
///
/// ```rust,ignore
/// with_encryption_key(&mut mkvs, &key, |mkvs| mkvs.get(b"foo"))
/// ```
pub fn with_encryption_key<F, R>(mkvs: &mut MKVS, key: &[u8], f: F) -> R
where
    F: FnOnce(&mut MKVS) -> R,
{
    mkvs.set_encryption_key(Some(key));
    let result = f(mkvs);
    mkvs.set_encryption_key(None);

    result
}

// Re-exports.
pub use self::{cas_patricia_trie::CASPatriciaTrie, urkel::UrkelTree};
