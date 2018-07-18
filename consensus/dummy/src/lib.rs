//! Ekiden dummy consensus backend.
#![feature(try_from)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
extern crate exonum_rocksdb;
extern crate serde;
extern crate serde_cbor;

extern crate ekiden_common;
extern crate ekiden_consensus_base;
#[macro_use]
extern crate ekiden_di;
extern crate ekiden_registry_base;
extern crate ekiden_scheduler_base;
extern crate ekiden_storage_base;

mod backend;
mod commitment;
mod signer;
mod state_storage;

pub use backend::DummyConsensusBackend;
pub use signer::DummyConsensusSigner;
pub use state_storage::StateStorage;
