#![feature(try_from)]

//! Ekiden registry interface.
extern crate byteorder;
extern crate ekiden_common;
extern crate ekiden_registry_api;
extern crate grpcio;
extern crate protobuf;

pub mod contract_backend;
pub mod contract_service;
pub mod entity_backend;
pub mod entity_service;
pub mod test;

pub use contract_backend::*;
pub use contract_service::*;
pub use entity_backend::*;
pub use entity_service::*;
