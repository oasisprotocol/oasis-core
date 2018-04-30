#![feature(try_from)]

//! Ekiden registry interface.
extern crate byteorder;
extern crate ekiden_common;
extern crate ekiden_registry_api;
extern crate grpcio;
extern crate protobuf;

pub mod backend;
pub mod registry_service;

pub use backend::*;
pub use registry_service::*;
