#![feature(core_intrinsics)]
#![feature(test)]
#![feature(panic_unwind)]

#[cfg(target_env = "sgx")]
extern crate sgx_trts;
#[cfg(target_env = "sgx")]
extern crate sgx_types;
#[cfg(target_env = "sgx")]
extern crate sgx_unwind;

#[macro_use]
extern crate lazy_static;
extern crate protobuf;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate bincode;

extern crate ekiden_common;
extern crate ekiden_enclave_common;
extern crate ekiden_enclave_trusted;
extern crate ekiden_keymanager_client;
extern crate ekiden_keymanager_common;
extern crate ekiden_storage_base;
#[cfg(not(target_env = "sgx"))]
extern crate ekiden_storage_dummy;
extern crate ekiden_storage_lru;

#[doc(hidden)]
pub mod ecalls;
#[cfg(target_env = "sgx")]
pub mod untrusted;

pub mod handle;
pub use handle::{DBKeyManagerConfig, DatabaseHandle};

pub mod patricia_trie;
#[macro_use]
pub mod schema;

use ekiden_common::{bytes::H256, error::Result};
use ekiden_keymanager_common::{ContractId, StateKeyType};

/// Database interface exposed to contracts.
pub trait Database {
    /// Returns true if the database contains a value for the specified key.
    fn contains_key(&self, key: &[u8]) -> bool;

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

    /// Set the root hash of the database state.
    fn set_root_hash(&mut self, root_hash: H256) -> Result<()>;

    /// Return the root hash of the database state.
    ///
    /// Note that without calling `commit` this will exclude any uncommitted
    /// modifications to the database state.
    fn get_root_hash(&self) -> H256;

    /// Commit all database changes to the underlying store.
    fn commit(&mut self) -> Result<H256>;

    /// Rollback any pending changes.
    fn rollback(&mut self);

    /// Run the given closure in an encrypted context for given contract. Will use
    /// the key manager client to fetch the necessary encryption key associated
    /// with `contract_id`.
    fn with_encryption<F, R>(&mut self, contract_id: ContractId, f: F) -> R
    where
        F: FnOnce(&mut DatabaseHandle) -> R;

    /// Run the given closure in an encrypted context for the given `state_key`.
    fn with_encryption_key<F, R>(&mut self, key: StateKeyType, f: F) -> R
    where
        F: FnOnce(&mut DatabaseHandle) -> R;
}
