//! Ekiden storage interface.
extern crate ekiden_common;
#[cfg(not(target_env = "sgx"))]
extern crate ekiden_storage_api;
#[cfg(not(target_env = "sgx"))]
extern crate grpcio;

pub mod backend;
pub mod mapper;
#[cfg(not(target_env = "sgx"))]
pub mod service;

pub use backend::*;
pub use mapper::*;
#[cfg(not(target_env = "sgx"))]
pub use service::*;
