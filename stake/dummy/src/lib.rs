//! Ekiden dummy registry backend.
extern crate ekiden_common;
extern crate ekiden_core;
#[macro_use]
extern crate ekiden_di;
extern crate ekiden_stake_api;
extern crate ekiden_stake_base;
extern crate serde;
extern crate serde_cbor;
extern crate clap;

mod stake;

pub use stake::DummyStakeEscrowBackend;
