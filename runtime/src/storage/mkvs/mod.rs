//! Merklized key-value store.
use failure::Fallible;

use serde_derive::{Deserialize, Serialize};

use crate::common::crypto::hash::Hash;

pub mod cas_patricia_trie;
pub mod urkel;

/// The type of entry in the log.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LogEntryKind {
    Insert,
    Delete,
}

/// An entry in the write log, describing a single update.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct LogEntry {
    /// The key that was inserted or deleted.
    pub key: Vec<u8>,
    /// The inserted value, or `None` if the key was deleted.
    pub value: Option<Vec<u8>>,
}

impl LogEntry {
    pub fn kind(&self) -> LogEntryKind {
        if self.value.is_none() {
            LogEntryKind::Delete
        } else {
            LogEntryKind::Insert
        }
    }
}

/// The write log.
///
/// The keys in the write log must be unique.
pub type WriteLog = Vec<LogEntry>;

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
    fn commit(&mut self) -> Fallible<(WriteLog, Hash)>;

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
