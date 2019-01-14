#![feature(test, try_from)]

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
#[macro_use]
extern crate clap;
#[cfg(not(target_env = "sgx"))]
extern crate get_if_addrs;
#[macro_use]
extern crate log;
#[cfg(not(target_env = "sgx"))]
extern crate openssl;
pub extern crate ring;
extern crate rustc_hex;
extern crate serde;
extern crate serde_bytes;
extern crate serde_cbor;
#[macro_use]
extern crate serde_derive;
#[cfg(not(target_env = "sgx"))]
pub extern crate tokio;
pub extern crate untrusted;

extern crate ekiden_common_api;
#[allow(unused_imports)]
#[macro_use]
extern crate ekiden_di;

pub mod address;
pub mod bytes;
pub mod drbg;
pub mod entity;
pub mod error;
pub mod futures;
pub mod hash;
pub mod node;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
pub mod macros;
pub mod mrae;
#[cfg(not(target_env = "sgx"))]
pub mod node_group;
#[macro_use]
pub mod profiling;
#[macro_use]
pub mod protobuf;
pub mod random;
#[cfg(not(target_env = "sgx"))]
pub mod remote_node;
pub mod signature;
#[macro_use]
pub mod uint;
#[cfg(not(target_env = "sgx"))]
pub mod environment;
pub mod identity;
pub mod subscribers;
pub mod testing;
pub mod usize_iterable_hashmap;
pub mod usize_iterable_hashset;
pub mod x509;
