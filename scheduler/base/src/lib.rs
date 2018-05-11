//! Ekiden scheduler interface.
#![feature(try_from)]

extern crate protobuf;
extern crate serde;
#[macro_use]
extern crate serde_derive;

extern crate ekiden_common;
extern crate ekiden_scheduler_api;

pub mod backend;

pub use backend::*;
