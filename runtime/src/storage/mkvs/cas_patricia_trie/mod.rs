//! A patricia trie MKVS backed by CAS.
use std::{collections::HashMap, sync::Arc};

use failure::Fallible;

use crate::{
    common::crypto::{
        hash::Hash,
        mrae::{
            nonce::NONCE_SIZE,
            sivaessha2::{SivAesSha2, KEY_SIZE},
        },
    },
    storage::{mkvs::WriteLog, CAS, MKVS},
};

pub mod nibble;
pub mod node;
pub mod trie;

use self::trie::PatriciaTrie;

/// Encryption context.
///
/// This contains the MRAE context for encrypting and decrypting keys and
/// values stored in the database.
/// It is set up with db.with_encryption() and lasts only for the duration of
/// the closure that's passed to that method.
struct EncryptionContext {
    /// MRAE context.
    mrae_ctx: SivAesSha2,
    /// Nonce for the MRAE context (should be unique for all time for a given key).
    nonce: Vec<u8>,
}

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
    /// Encryption context with which to perform all operations (optional).
    enc_ctx: Option<EncryptionContext>,
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
            enc_ctx: None,
        }
    }
}

impl MKVS for CASPatriciaTrie {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        // Encrypt key using the encryption context, if it's present.
        let key = match self.enc_ctx {
            Some(ref ctx) => ctx
                .mrae_ctx
                .seal(ctx.nonce.clone(), key.to_vec(), vec![])
                .unwrap(),
            None => key.to_vec(),
        };

        // Fetch the current value by first checking the list of pending operations if they
        // affect the given key.
        let value = match self.pending_ops.get(&key) {
            Some(Operation::Insert(value)) => Some(value.clone()),
            Some(Operation::Remove) => None,
            None => self.trie.get(self.root_hash.clone(), &key),
        };

        if self.enc_ctx.is_some() && value.is_some() {
            // Decrypt value using the encryption context.
            let ctx = self.enc_ctx.as_ref().unwrap();

            let decrypted = ctx.mrae_ctx.open(ctx.nonce.clone(), value.unwrap(), vec![]);

            decrypted.ok()
        } else {
            value
        }
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        let previous_value = self.get(key);

        let value = match self.enc_ctx {
            Some(ref ctx) => {
                // Encrypt value using the encryption context.
                ctx.mrae_ctx
                    .seal(ctx.nonce.clone(), value.to_vec(), vec![])
                    .unwrap()
            }
            None => value.to_vec(),
        };

        // Encrypt key using the encryption context, if it's present.
        let key = match self.enc_ctx {
            Some(ref ctx) => ctx
                .mrae_ctx
                .seal(ctx.nonce.clone(), key.to_vec(), vec![])
                .unwrap(),
            None => key.to_vec(),
        };

        // Add a pending insert operation for the given key.
        self.pending_ops.insert(key, Operation::Insert(value));

        previous_value
    }

    fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let previous_value = self.get(key);

        // Encrypt key using the encryption context, if it's present.
        let key = match self.enc_ctx {
            Some(ref ctx) => ctx
                .mrae_ctx
                .seal(ctx.nonce.clone(), key.to_vec(), vec![])
                .unwrap(),
            None => key.to_vec(),
        };

        // Add a pending remove operation for the given key.
        self.pending_ops.insert(key, Operation::Remove);

        previous_value
    }

    fn commit(&mut self) -> Fallible<(WriteLog, Hash)> {
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

    fn set_encryption_key(&mut self, key: Option<&[u8]>) {
        if key.is_none() {
            self.enc_ctx = None;
            return;
        }

        // Split the state_key into a MRAE key and nonce.
        let raw_key = key.unwrap();
        let key: Vec<u8> = raw_key[..KEY_SIZE].to_vec();
        let nonce: Vec<u8> = raw_key[KEY_SIZE..KEY_SIZE + NONCE_SIZE].to_vec();

        // Set up encryption context.
        self.enc_ctx = Some(EncryptionContext {
            mrae_ctx: SivAesSha2::new(key).unwrap(),
            nonce,
        });
    }
}
