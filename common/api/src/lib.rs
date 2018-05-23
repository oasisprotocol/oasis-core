#![feature(try_from)]

#[cfg(not(target_env = "sgx"))]
extern crate futures;
#[cfg(not(target_env = "sgx"))]
extern crate grpcio;
extern crate protobuf;

mod generated;

pub use generated::common::*;
#[cfg(not(target_env = "sgx"))]
pub use generated::common_grpc::*;
