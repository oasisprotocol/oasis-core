//! Ekiden storage interface.
extern crate ekiden_common;

pub mod backend;
pub mod mapper;

pub use backend::*;
pub use mapper::*;
