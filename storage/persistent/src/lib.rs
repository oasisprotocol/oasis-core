//! Ekiden persistent storage backend.
extern crate ekiden_common;
#[macro_use]
extern crate ekiden_di;
extern crate ekiden_epochtime;
extern crate ekiden_storage_base;

extern crate exonum_rocksdb;
extern crate serde_cbor;

mod backend;

pub use backend::*;
