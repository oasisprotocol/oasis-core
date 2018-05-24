//! Ekiden dummy storage backend.
extern crate ekiden_common;
#[macro_use]
extern crate ekiden_di;
extern crate ekiden_storage_base;

mod backend;

pub use backend::DummyStorageBackend;
