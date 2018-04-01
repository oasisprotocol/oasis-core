#![feature(use_extern_macros)]

extern crate sgx_types;

extern crate base64;
extern crate byteorder;
extern crate protobuf;
extern crate serde_json;
extern crate sodalite;

#[macro_use]
extern crate ekiden_common;

pub mod identity;
pub mod quote;

// This is pub so that other crates can import our protos.
pub mod generated;

pub mod api {
    pub use generated::enclave_identity::*;
}
