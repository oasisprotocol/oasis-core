#![feature(core_intrinsics)]
#![feature(use_extern_macros)]

#[cfg(target_env = "sgx")]
extern crate sgx_trts;
#[cfg(target_env = "sgx")]
extern crate sgx_types;

#[macro_use]
extern crate lazy_static;
extern crate protobuf;
extern crate serde;
extern crate serde_cbor;
#[macro_use]
extern crate serde_derive;

extern crate ekiden_common;
extern crate ekiden_enclave_trusted;
extern crate ekiden_storage_base;
#[cfg(not(target_env = "sgx"))]
extern crate ekiden_storage_dummy;
extern crate ekiden_storage_lru;

#[doc(hidden)]
pub mod ecalls;
#[cfg(target_env = "sgx")]
pub mod untrusted;

pub mod handle;
pub use handle::DatabaseHandle;

pub mod patricia_trie;
#[macro_use]
pub mod schema;

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

    /// Clear database state.
    fn clear(&mut self);
}
