//! Ekiden dummy consensus backend.
#[macro_use]
extern crate log;

extern crate ekiden_common;
extern crate ekiden_consensus_base;

mod backend;

pub use backend::DummyConsensusBackend;
