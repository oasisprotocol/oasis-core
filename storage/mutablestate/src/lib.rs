//! Ekiden dummy root hash backend.

extern crate ekiden_common;
#[macro_use]
extern crate ekiden_di;
extern crate exonum_rocksdb;

mod state_storage;

pub use state_storage::StateStorage;
