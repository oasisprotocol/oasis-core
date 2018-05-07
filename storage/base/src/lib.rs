//! Ekiden storage interface.
extern crate ekiden_common;
extern crate ekiden_storage_api;
extern crate grpcio;

pub mod backend;
pub mod service;

pub use backend::*;
pub use service::*;
