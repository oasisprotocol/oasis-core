//! Ekiden scheduler interface.
extern crate serde;
#[macro_use]
extern crate serde_derive;

extern crate ekiden_common;

pub mod backend;

pub use backend::*;
