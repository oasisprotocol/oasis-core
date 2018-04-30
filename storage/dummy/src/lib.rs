//! Ekiden dummy storage backend.
extern crate ekiden_common;
extern crate ekiden_storage_base;

mod backend;

pub use backend::DummyStorageBackend;
