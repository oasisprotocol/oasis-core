//! Merklized key-value store.
use std::{
    iter,
    ops::{Deref, DerefMut},
};

use anyhow::{Error, Result};

use crate::common::{crypto::hash::Hash, namespace::Namespace};

#[macro_use]
mod tree;
mod cache;
#[cfg(test)]
pub mod interop;
pub mod marshal;
pub mod sync;
#[cfg(test)]
mod tests;

pub use tree::{Depth, Key, NodeBox, OverlayTree, Root, RootType, Tree};

/// The type of entry in the log.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LogEntryKind {
    Insert,
    Delete,
}

/// An entry in the write log, describing a single update.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, cbor::Encode, cbor::Decode)]
#[cbor(as_array)]
pub struct LogEntry {
    /// The key that was inserted or deleted.
    pub key: Vec<u8>,
    /// The inserted value (empty if the key was deleted).
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

/// The write log.
///
/// The keys in the write log must be unique.
pub type WriteLog = Vec<LogEntry>;

/// A key prefix.
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord, cbor::Encode, cbor::Decode)]
#[cbor(transparent)]
pub struct Prefix(Vec<u8>);

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

impl From<Prefix> for Vec<u8> {
    fn from(val: Prefix) -> Self {
        val.0
    }
}

impl From<Vec<u8>> for Prefix {
    fn from(v: Vec<u8>) -> Prefix {
        Prefix(v)
    }
}

/// Merklized key-value store.
pub trait MKVS {
    /// Fetch entry with given key.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Check if the local MKVS cache contains the given key.
    ///
    /// While get can be used to check if the MKVS as a whole contains
    /// a given key, this function specifically guarantees that no remote
    /// syncing will be invoked, only checking the local cache.
    fn cache_contains_key(&self, key: &[u8]) -> bool;

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

    /// Populate the in-memory tree with nodes for keys starting with given prefixes.
    fn prefetch_prefixes(&self, prefixes: &[Prefix], limit: u16);

    /// Returns an iterator over the tree.
    fn iter(&self) -> Box<dyn Iterator + '_>;

    /// Commit all database changes to the underlying store.
    fn commit(&mut self, namespace: Namespace, version: u64) -> Result<(WriteLog, Hash)>;
}

/// Merklized key-value store where methods return errors instead of panicking.
pub trait FallibleMKVS {
    /// Fetch entry with given key.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Check if the local MKVS cache contains the given key.
    ///
    /// While get can be used to check if the MKVS as a whole contains
    /// a given key, this function specifically guarantees that no remote
    /// syncing will be invoked, only checking the local cache.
    fn cache_contains_key(&self, key: &[u8]) -> bool;

    /// Update entry with given key.
    ///
    /// If the database did not have this key present, [`None`] is returned.
    ///
    /// If the database did have this key present, the value is updated, and the old value is
    /// returned.
    ///
    /// [`None`]: std::option::Option
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Remove entry with given key, returning the value at the key if the key was previously
    /// in the database.
    fn remove(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Populate the in-memory tree with nodes for keys starting with given prefixes.
    fn prefetch_prefixes(&self, prefixes: &[Prefix], limit: u16) -> Result<()>;

    /// Returns an iterator over the tree.
    fn iter(&self) -> Box<dyn Iterator + '_>;

    /// Commit all database changes to the underlying store.
    fn commit(&mut self, namespace: Namespace, version: u64) -> Result<Hash>;
}

/// Immutable merkalized key value store.
pub trait ImmutableMKVS {
    /// Fetch entry with given key.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Populate the in-memory tree with nodes for keys starting with given prefixes.
    fn prefetch_prefixes(&self, prefixes: &[Prefix], limit: u16) -> Result<()>;

    /// Returns an iterator over the tree.
    fn iter(&self) -> Box<dyn Iterator + '_>;
}

impl<T> ImmutableMKVS for T
where
    T: FallibleMKVS,
{
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        T::get(self, key)
    }

    fn prefetch_prefixes(&self, prefixes: &[Prefix], limit: u16) -> Result<()> {
        T::prefetch_prefixes(self, prefixes, limit)
    }

    fn iter(&self) -> Box<dyn Iterator + '_> {
        T::iter(self)
    }
}

/// An MKVS iterator.
pub trait Iterator: iter::Iterator<Item = (Vec<u8>, Vec<u8>)> {
    /// Sets the number of next elements to prefetch.
    fn set_prefetch(&mut self, prefetch: usize);

    /// Return whether the iterator is valid.
    fn is_valid(&self) -> bool;

    /// Return the error that occurred during iteration if any.
    fn error(&self) -> &Option<Error>;

    /// Moves the iterator to the first key in the tree.
    fn rewind(&mut self);

    /// Moves the iterator either at the given key or at the next larger key.
    fn seek(&mut self, key: &[u8]);

    /// The key under the iterator.
    fn get_key(&self) -> &Option<Key>;

    /// The value under the iterator.
    fn get_value(&self) -> &Option<Vec<u8>>;

    /// Advance the iterator to the next key.
    fn next(&mut self);
}

impl<T: MKVS + ?Sized> MKVS for &mut T {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        T::get(self, key)
    }

    fn cache_contains_key(&self, key: &[u8]) -> bool {
        T::cache_contains_key(self, key)
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        T::insert(self, key, value)
    }

    fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        T::remove(self, key)
    }

    fn prefetch_prefixes(&self, prefixes: &[Prefix], limit: u16) {
        T::prefetch_prefixes(self, prefixes, limit)
    }

    fn iter(&self) -> Box<dyn Iterator + '_> {
        T::iter(self)
    }

    fn commit(&mut self, namespace: Namespace, version: u64) -> Result<(WriteLog, Hash)> {
        T::commit(self, namespace, version)
    }
}

impl<T: FallibleMKVS + ?Sized> FallibleMKVS for &mut T {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        T::get(self, key)
    }

    fn cache_contains_key(&self, key: &[u8]) -> bool {
        T::cache_contains_key(self, key)
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        T::insert(self, key, value)
    }

    fn remove(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        T::remove(self, key)
    }

    fn prefetch_prefixes(&self, prefixes: &[Prefix], limit: u16) -> Result<()> {
        T::prefetch_prefixes(self, prefixes, limit)
    }

    fn iter(&self) -> Box<dyn Iterator + '_> {
        T::iter(self)
    }

    fn commit(&mut self, namespace: Namespace, version: u64) -> Result<Hash> {
        T::commit(self, namespace, version)
    }
}

#[cfg(test)]
mod _tests {
    use super::*;

    #[test]
    fn test_write_log_serialization() {
        let write_log = vec![LogEntry {
            key: b"foo".to_vec(),
            value: Some(b"bar".to_vec()),
        }];

        let raw = cbor::to_vec(write_log.clone());
        let deserialized: WriteLog = cbor::from_slice(&raw).unwrap();

        assert_eq!(write_log, deserialized);
    }
}
