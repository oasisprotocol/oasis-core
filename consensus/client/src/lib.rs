#![feature(try_from)]

//! Ekiden consensus frontend.
extern crate ekiden_common;
extern crate ekiden_consensus_api;
extern crate ekiden_consensus_base;
extern crate grpcio;

pub mod client;

pub use client::*;
