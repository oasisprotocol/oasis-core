//! Ekiden storage frontend.
extern crate ekiden_common;
#[macro_use]
extern crate ekiden_di;
extern crate ekiden_registry_base;
extern crate ekiden_scheduler_base;
extern crate ekiden_storage_base;
extern crate ekiden_tracing;

extern crate futures;
extern crate grpcio;
extern crate protobuf;
extern crate rustracing;

pub mod client;
mod generated;

pub use client::*;
