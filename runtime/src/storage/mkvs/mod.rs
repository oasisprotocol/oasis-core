//! Merklized key-value store.
use base64;
use failure::Fallible;
use io_context::Context;
use serde::{self, ser::SerializeSeq, Serializer};
use serde_bytes::Bytes;
use serde_derive::Deserialize;

use crate::common::{crypto::hash::Hash, roothash::Namespace};

pub mod urkel;

/// The type of entry in the log.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LogEntryKind {
    Insert,
    Delete,
}

/// An entry in the write log, describing a single update.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Hash)]
pub struct LogEntry {
    /// The key that was inserted or deleted.
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    /// The inserted value (empty if the key was deleted).
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

impl LogEntry {
    pub fn new(key: &[u8], value: &[u8]) -> Self {
        Self {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }

    pub fn kind(&self) -> LogEntryKind {
        if self.value.is_empty() {
            LogEntryKind::Delete
        } else {
            LogEntryKind::Insert
        }
    }
}

impl serde::Serialize for LogEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut seq = serializer.serialize_seq(Some(2))?;
        if is_human_readable {
            seq.serialize_element(&base64::encode(&self.key))?;
            seq.serialize_element(&base64::encode(&self.value))?;
        } else {
            seq.serialize_element(&Bytes::new(&self.key))?;
            seq.serialize_element(&Bytes::new(&self.value))?;
        }
        seq.end()
    }
}

/// The write log.
///
/// The keys in the write log must be unique.
pub type WriteLog = Vec<LogEntry>;

/// Merklized key-value store.
pub trait MKVS: Send + Sync {
    /// Fetch entry with given key.
    fn get(&self, ctx: Context, key: &[u8]) -> Option<Vec<u8>>;

    /// Update entry with given key.
    ///
    /// If the database did not have this key present, [`None`] is returned.
    ///
    /// If the database did have this key present, the value is updated, and the old value is
    /// returned.
    ///
    /// [`None`]: std::option::Option
    fn insert(&mut self, ctx: Context, key: &[u8], value: &[u8]) -> Option<Vec<u8>>;

    /// Remove entry with given key, returning the value at the key if the key was previously
    /// in the database.
    fn remove(&mut self, ctx: Context, key: &[u8]) -> Option<Vec<u8>>;

    /// Commit all database changes to the underlying store.
    fn commit(
        &mut self,
        ctx: Context,
        namespace: Namespace,
        round: u64,
    ) -> Fallible<(WriteLog, Hash)>;

    /// Rollback any pending changes.
    fn rollback(&mut self);
}

// Re-exports.
pub use self::urkel::UrkelTree;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::cbor;

    #[test]
    fn test_write_log_serialization() {
        let write_log = vec![LogEntry {
            key: b"foo".to_vec(),
            value: b"bar".to_vec(),
        }];

        let raw = cbor::to_vec(&write_log);
        let deserialized: WriteLog = cbor::from_slice(&raw).unwrap();

        assert_eq!(write_log, deserialized);
    }
}
