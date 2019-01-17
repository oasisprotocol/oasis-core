//! Ekiden root hash remote client.
#![feature(try_from)]

extern crate ekiden_common;
extern crate ekiden_roothash_api;
extern crate ekiden_roothash_base;
#[macro_use]
extern crate ekiden_di;

extern crate grpcio;

pub mod client;

pub use client::*;
