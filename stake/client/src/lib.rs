//! Ekiden stake client.
#![feature(try_from)]

extern crate ekiden_common;
extern crate ekiden_stake_api;
extern crate ekiden_stake_base;
extern crate grpcio;

pub mod stake;

pub use stake::*;
