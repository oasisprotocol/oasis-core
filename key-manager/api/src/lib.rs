extern crate protobuf;
extern crate serde;

#[macro_use]
extern crate ekiden_core;

#[macro_use]
mod api;
mod generated;

pub use generated::api::{GetOrCreateKeyRequest, GetOrCreateKeyResponse};
