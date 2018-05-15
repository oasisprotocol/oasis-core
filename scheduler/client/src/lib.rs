#![feature(try_from)]

//! Ekiden scheduler client.
extern crate ekiden_common;
extern crate ekiden_scheduler_api;
extern crate ekiden_scheduler_base;
extern crate grpcio;

pub mod client;

pub use client::*;
