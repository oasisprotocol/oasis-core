//! Ekiden registry interface.
#![feature(try_from)]

extern crate byteorder;
#[macro_use]
extern crate ekiden_common;
extern crate ekiden_epochtime;
extern crate ekiden_registry_api;
extern crate grpcio;
extern crate protobuf;

pub mod entity_backend;
pub mod runtime_backend;
pub mod test;

pub use entity_backend::*;
pub use runtime_backend::*;
