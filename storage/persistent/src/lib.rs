//! Ekiden persistent storage backend.
extern crate ekiden_common;
extern crate ekiden_storage_base;

extern crate base64;
extern crate serde_cbor;
extern crate sled;

mod backend;

pub use backend::*;
