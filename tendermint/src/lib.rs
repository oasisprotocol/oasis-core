//! Tendermint-based backends.
//!
//! This package includes all Tendermint ABCI applications and clients.
#![feature(try_from)]

extern crate base64;
extern crate bytes;
extern crate integer_encoding;
extern crate jsonrpc_core;
#[macro_use]
extern crate log;
extern crate protobuf;
extern crate serde;
extern crate serde_cbor;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_codec;
extern crate tokio_tungstenite;
extern crate tungstenite;

#[macro_use]
extern crate ekiden_common;
#[macro_use]
extern crate ekiden_di;
extern crate ekiden_consensus_base;

pub mod abci;
pub mod application;
pub mod client;
pub mod commitment;
