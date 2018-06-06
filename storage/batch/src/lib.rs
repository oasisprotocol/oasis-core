//! Ekiden batch storage backend.
extern crate ekiden_common;
extern crate ekiden_storage_base;
extern crate ekiden_storage_dummy;

#[macro_use]
extern crate log;

mod backend;

pub use backend::BatchStorageBackend;
