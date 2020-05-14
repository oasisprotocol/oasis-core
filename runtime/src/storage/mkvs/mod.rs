//! Merklized key-value store.
use std::ops::{Deref, DerefMut};

use base64;
use failure::Fallible;
use io_context::Context;
use serde::{self, ser::SerializeSeq, Serializer};
use serde_bytes::Bytes;
use serde_derive::{Deserialize, Serialize};

use crate::common::{crypto::hash::Hash, roothash::Namespace};

#[macro_use]
mod tree;
mod cache;
#[cfg(test)]
mod interop;
pub mod marshal;
pub mod sync;
#[cfg(test)]
mod tests;

pub use tree::{Depth, Key, NodeBox, Root, Tree};

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
    pub value: Option<Vec<u8>>,
}

impl LogEntry {
    pub fn new(key: &[u8], value: &[u8]) -> Self {
        Self {
            key: key.to_owned(),
            value: Some(value.to_owned()),
        }
    }

    pub fn kind(&self) -> LogEntryKind {
        match self.value {
            Some(_) => LogEntryKind::Insert,
            None => LogEntryKind::Delete,
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
            seq.serialize_element(&self.value.as_ref().map(|v| base64::encode(v)))?;
        } else {
            seq.serialize_element(&Bytes::new(&self.key))?;
            seq.serialize_element(&self.value.as_ref().map(|v| Bytes::new(v)))?;
        }
        seq.end()
    }
}

/// The write log.
///
/// The keys in the write log must be unique.
pub type WriteLog = Vec<LogEntry>;

/// A key prefix.
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Prefix(#[serde(with = "serde_bytes")] Vec<u8>);

impl AsRef<[u8]> for Prefix {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Prefix {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Prefix {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Into<Vec<u8>> for Prefix {
    fn into(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for Prefix {
    fn from(v: Vec<u8>) -> Prefix {
        Prefix(v)
    }
}

/// Merklized key-value store.
pub trait MKVS: Send + Sync {
    /// Fetch entry with given key.
    fn get(&self, ctx: Context, key: &[u8]) -> Option<Vec<u8>>;

    /// Check if the local MKVS cache contains the given key.
    ///
    /// While get can be used to check if the MKVS as a whole contains
    /// a given key, this function specifically guarantees that no remote
    /// syncing will be invoked, only checking the local cache.
    fn cache_contains_key(&self, ctx: Context, key: &[u8]) -> bool;

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

    /// Populate the in-memory tree with nodes for keys starting with given prefixes.
    fn prefetch_prefixes(&self, ctx: Context, prefixes: &Vec<Prefix>, limit: u16);

    /// Commit all database changes to the underlying store.
    fn commit(
        &mut self,
        ctx: Context,
        namespace: Namespace,
        version: u64,
    ) -> Fallible<(WriteLog, Hash)>;

    /// Rollback any pending changes.
    fn rollback(&mut self);
}

#[cfg(test)]
mod _tests {
    use super::*;

    use crate::common::cbor;

    #[test]
    fn test_write_log_serialization() {
        let write_log = vec![LogEntry {
            key: b"foo".to_vec(),
            value: Some(b"bar".to_vec()),
        }];

        let raw = cbor::to_vec(&write_log);
        let deserialized: WriteLog = cbor::from_slice(&raw).unwrap();

        assert_eq!(write_log, deserialized);
    }
}
