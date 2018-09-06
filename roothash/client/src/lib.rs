//! Ekiden root hash remote client.
#![feature(try_from)]

extern crate ekiden_common;
extern crate ekiden_roothash_api;
extern crate ekiden_roothash_base;
#[macro_use]
extern crate ekiden_di;

extern crate grpcio;
extern crate serde;
extern crate serde_cbor;
#[macro_use]
extern crate serde_derive;

pub mod client;
pub mod commitment;
pub mod signer;

pub use client::*;
pub use signer::InternalRootHashSigner;
