//! Ekiden persistent storage backend.
extern crate ekiden_common;
#[macro_use]
extern crate ekiden_di;
extern crate ekiden_epochtime;
extern crate ekiden_storage_base;

extern crate serde_cbor;
extern crate sled;

mod backend;

pub use backend::*;
