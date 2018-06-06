#![feature(try_from)]

//! Ekiden consensus frontend.
extern crate ekiden_common;
extern crate ekiden_consensus_api;
extern crate ekiden_consensus_base;
#[macro_use]
extern crate ekiden_di;

extern crate grpcio;

pub mod client;

pub use client::*;
