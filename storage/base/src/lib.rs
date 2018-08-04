//! Ekiden storage interface.
#[macro_use]
extern crate ekiden_common;
#[cfg(not(target_env = "sgx"))]
extern crate ekiden_storage_api;
#[cfg(not(target_env = "sgx"))]
extern crate grpcio;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate log;
#[cfg(not(target_env = "sgx"))]
extern crate protobuf;

pub mod backend;
pub mod batch;
pub mod mapper;
#[cfg(not(target_env = "sgx"))]
pub mod service;

pub use backend::*;
pub use batch::BatchStorage;
pub use mapper::*;
#[cfg(not(target_env = "sgx"))]
pub use service::*;
