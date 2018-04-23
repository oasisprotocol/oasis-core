//! Ekiden persistent storage backend.
extern crate ekiden_common;
extern crate ekiden_storage_base;

extern crate sled;
extern crate tar;

mod backend;

pub use backend::PersistentStorageBackend;
