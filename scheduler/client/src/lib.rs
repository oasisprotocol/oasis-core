#![feature(try_from)]

//! Ekiden scheduler client.
extern crate ekiden_common;
#[macro_use]
extern crate ekiden_di;
extern crate ekiden_scheduler_api;
extern crate ekiden_scheduler_base;

extern crate grpcio;

pub mod client;

pub use client::*;
