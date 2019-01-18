//! Ekiden root hash interface.
#![feature(try_from)]

extern crate serde;
extern crate serde_cbor;
#[macro_use]
extern crate serde_derive;
extern crate serde_bytes;

extern crate ekiden_common;
#[cfg(not(target_env = "sgx"))]
extern crate ekiden_roothash_api;

#[cfg(not(target_env = "sgx"))]
pub mod backend;
#[cfg(not(target_env = "sgx"))]
pub mod block;
pub mod header;

#[cfg(not(target_env = "sgx"))]
pub use backend::*;
#[cfg(not(target_env = "sgx"))]
pub use block::*;
pub use header::*;
