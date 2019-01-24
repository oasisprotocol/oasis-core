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
#[cfg(not(target_env = "sgx"))]
extern crate clap;
extern crate core;
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

pub mod address;
pub mod bytes;
pub mod drbg;
pub mod error;
pub mod futures;
pub mod hash;
pub mod mrae;
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
pub mod subscribers;
pub mod testing;
pub mod usize_iterable_hashmap;
pub mod usize_iterable_hashset;
pub mod x509;
