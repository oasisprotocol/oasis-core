#![feature(use_extern_macros, try_from)]

#[cfg(not(target_env = "sgx"))]
extern crate grpcio;

#[cfg(not(target_env = "sgx"))]
extern crate rand;

#[cfg(target_env = "sgx")]
extern crate sgx_rand;
#[cfg(target_env = "sgx")]
extern crate sgx_trts;

#[cfg(not(target_env = "sgx"))]
extern crate env_logger;
#[cfg(not(target_env = "sgx"))]
extern crate pretty_env_logger;

extern crate bigint;
extern crate byteorder;
extern crate chrono;
extern crate core;
#[cfg(not(target_env = "sgx"))]
extern crate get_if_addrs;
#[macro_use]
extern crate log;
pub extern crate ring;
extern crate rustc_hex;
extern crate serde;
extern crate serde_bytes;
extern crate serde_cbor;
#[macro_use]
extern crate serde_derive;
pub extern crate untrusted;

extern crate ekiden_common_api;
#[allow(unused_imports)]
#[macro_use]
extern crate ekiden_di;

pub mod address;
pub mod bytes;
pub mod contract;
pub mod drbg;
pub mod entity;
pub mod epochtime;
pub mod error;
pub mod futures;
pub mod hash;
pub mod node;
#[cfg(not(target_env = "sgx"))]
pub mod node_group;
#[macro_use]
pub mod profiling;
#[macro_use]
pub mod protobuf;
pub mod random;
pub mod signature;
#[macro_use]
pub mod uint;
pub mod environment;
pub mod subscribers;
pub mod testing;
