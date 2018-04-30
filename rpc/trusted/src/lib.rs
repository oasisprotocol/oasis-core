#![feature(use_extern_macros)]
#![feature(core_intrinsics)]

#[cfg(target_env = "sgx")]
extern crate sgx_tse;
#[cfg(target_env = "sgx")]
extern crate sgx_tseal;
#[cfg(target_env = "sgx")]
extern crate sgx_types;

extern crate futures;
#[macro_use]
extern crate lazy_static;
extern crate protobuf;
extern crate serde;
extern crate serde_cbor;
extern crate sodalite;

extern crate ekiden_common;
extern crate ekiden_enclave_common;
extern crate ekiden_enclave_trusted;
extern crate ekiden_rpc_client;
extern crate ekiden_rpc_common;

pub mod dispatcher;
pub mod error;
pub mod request;
pub mod response;

pub mod secure_channel;

#[macro_use]
mod macros;

mod untrusted;
pub mod client;
