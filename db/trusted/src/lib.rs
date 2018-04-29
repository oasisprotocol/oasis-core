#![feature(core_intrinsics)]
#![feature(use_extern_macros)]

extern crate bsdiff;
extern crate bzip2;
#[macro_use]
extern crate lazy_static;
extern crate protobuf;
extern crate serde;
extern crate serde_cbor;
extern crate sodalite;

#[macro_use]
extern crate ekiden_common;
extern crate ekiden_enclave_trusted;
extern crate ekiden_key_manager_client;

mod generated;

mod crypto;
mod diffs;
#[doc(hidden)]
pub mod ecalls;

pub mod handle;
pub use handle::DatabaseHandle;

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
