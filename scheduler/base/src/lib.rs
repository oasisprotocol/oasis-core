//! Ekiden scheduler interface.
#![feature(try_from)]

extern crate grpcio;
extern crate protobuf;
extern crate serde;
#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate ekiden_common;
extern crate ekiden_scheduler_api;

pub mod backend;
pub mod service;

pub use backend::*;
pub use service::*;
