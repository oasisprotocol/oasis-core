//! Ekiden dummy registry backend.
extern crate ekiden_common;
#[macro_use]
extern crate ekiden_di;
extern crate ekiden_registry_base;

extern crate serde_cbor;

mod contract;
mod entity;

pub use contract::DummyContractRegistryBackend;
pub use entity::DummyEntityRegistryBackend;
