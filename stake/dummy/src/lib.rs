//! Ekiden dummy registry backend.
extern crate ekiden_common;
extern crate ekiden_core;
#[macro_use]
extern crate ekiden_di;
extern crate ekiden_stake_api;
extern crate ekiden_stake_base;
extern crate serde;
extern crate serde_cbor;
#[macro_use]
extern crate clap;

mod stake;
mod usize_iterable_hashmap;
mod usize_iterable_hashset;

pub use stake::DummyStakeEscrowBackend;
pub use usize_iterable_hashmap::UsizeIterableHashMap;
pub use usize_iterable_hashset::UsizeIterableHashSet;
