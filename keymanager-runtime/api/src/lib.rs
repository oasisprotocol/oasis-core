//! Key manager API.
extern crate ekiden_runtime;
extern crate failure;
extern crate rand;
extern crate rustc_hex;
extern crate serde;
extern crate serde_bytes;
extern crate serde_derive;
extern crate x25519_dalek;

#[macro_use]
mod api;

// Re-exports.
pub use api::*;
