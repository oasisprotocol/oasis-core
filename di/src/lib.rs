//! Dependency injection.
#[cfg(all(feature = "cli", not(target_env = "sgx")))]
extern crate clap;
#[macro_use]
extern crate error_chain;

pub mod error;
#[macro_use]
pub mod macros;
pub mod di;

pub use di::*;
