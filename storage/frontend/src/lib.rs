//! Ekiden storage frontend.
extern crate ekiden_common;
extern crate ekiden_registry_base;
extern crate ekiden_scheduler_base;
extern crate ekiden_storage_api;
extern crate ekiden_storage_base;
extern crate grpcio;

pub mod client;
pub mod frontend;

pub use client::*;
pub use frontend::*;
