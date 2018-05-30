//! Ekiden dummy registry backend.
extern crate ekiden_common;
extern crate ekiden_registry_base;
extern crate serde_cbor;

mod contract;
mod entity;

pub use contract::DummyContractRegistryBackend;
pub use entity::DummyEntityRegistryBackend;
