//! Ekiden storage interface.
extern crate ekiden_beacon_api;
extern crate ekiden_common;
extern crate ekiden_epochtime;
extern crate grpcio;

pub mod backend;
pub mod service;

pub use backend::*;
pub use service::*;
