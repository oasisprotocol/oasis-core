//! A patricia trie MKVS backed by CAS.
use std::{collections::HashMap, sync::Arc};

use failure::Fallible;
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::{mkvs::WriteLog, CAS, MKVS},
};

pub mod nibble;
pub mod node;
pub mod trie;

use self::trie::PatriciaTrie;

/// Pending database operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Operation {
    /// Insert key with given value.
    Insert(Vec<u8>),
    /// Remove key.
    Remove,
}

pub struct CASPatriciaTrie {
    /// Patricia trie.
    trie: PatriciaTrie,
    /// Root hash.
    root_hash: Option<Hash>,
    /// Pending operations since the last root hash was set.
    pending_ops: HashMap<Vec<u8>, Operation>,
}

impl CASPatriciaTrie {
    pub fn new(cas: Arc<CAS>, root_hash: &Hash) -> Self {
        Self {
            trie: PatriciaTrie::new(cas),
            root_hash: if root_hash.is_empty() {
                None
            } else {
                Some(root_hash.clone())
            },
            pending_ops: HashMap::new(),
        }
    }
}

impl MKVS for CASPatriciaTrie {
    fn get(&self, _ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        let key = key.to_vec();

        // Fetch the current value by first checking the list of pending operations if they
        // affect the given key.
        let value = match self.pending_ops.get(&key.to_vec()) {
            Some(Operation::Insert(value)) => Some(value.clone()),
            Some(Operation::Remove) => None,
            None => self.trie.get(self.root_hash.clone(), &key),
        };

        value
    }

    fn insert(&mut self, ctx: Context, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        let previous_value = self.get(ctx, key);

        // Add a pending insert operation for the given key.
        self.pending_ops
            .insert(key.to_vec(), Operation::Insert(value.to_vec()));

        previous_value
    }

    fn remove(&mut self, ctx: Context, key: &[u8]) -> Option<Vec<u8>> {
        let previous_value = self.get(ctx, key);

        // Add a pending remove operation for the given key.
        self.pending_ops.insert(key.to_vec(), Operation::Remove);

        previous_value
    }

    fn commit(&mut self, _ctx: Context) -> Fallible<(WriteLog, Hash)> {
        // Commit all pending writes to the trie.
        let mut root_hash = self.root_hash.clone();
        for (key, value) in self.pending_ops.drain() {
            match value {
                Operation::Insert(value) => {
                    root_hash = Some(self.trie.insert(root_hash, &key, &value));
                }
                Operation::Remove => {
                    root_hash = self.trie.remove(root_hash, &key);
                }
            }
        }

        self.root_hash = root_hash;

        Ok((
            Vec::new(),
            self.root_hash.clone().unwrap_or_else(|| Hash::empty_hash()),
        ))
    }

    fn rollback(&mut self) {
        self.pending_ops.clear();
    }
}
