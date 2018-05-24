//! Ekiden LRU cache storage backend.
extern crate lru_cache;

extern crate ekiden_common;
extern crate ekiden_storage_base;

mod backend;

pub use backend::LruCacheStorageBackend;
