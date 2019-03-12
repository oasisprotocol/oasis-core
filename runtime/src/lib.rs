//! Ekiden runtime SDK.
//!
//! # Examples
//!
//! To create a minimal runtime that doesn't expose any APIs to the
//! outside world, you need to call the `start_runtime` function:
//! ```rust,ignore
//! ekiden_runtime::start_runtime(Some(Box::new(reg)));
//! ```
//!
//! This will start the required services needed to communicate with
//! the worker host.
#![feature(test)]

#[macro_use]
extern crate slog;
extern crate crossbeam;
extern crate lazy_static;
extern crate serde_bytes;
extern crate serde_cbor;
extern crate serde_derive;
extern crate serde_json;
extern crate slog_json;
#[macro_use]
extern crate failure;
extern crate base64;
extern crate bincode;
extern crate chrono;
extern crate io_context;
extern crate pem_iterator;
extern crate percent_encoding;
extern crate ring;
extern crate rustc_hex;
extern crate snow;
extern crate tokio_current_thread;
extern crate tokio_executor;
extern crate webpki;

#[macro_use]
pub mod common;
pub mod dispatcher;
pub mod executor;
pub mod init;
pub mod macros;
pub mod protocol;
pub mod rak;
pub mod rpc;
pub mod storage;
pub mod tracing;
pub mod transaction;
pub mod types;

// Re-exports.
pub use self::{
    init::start_runtime, protocol::Protocol, rpc::dispatcher::Dispatcher as RpcDispatcher,
    transaction::dispatcher::Dispatcher as TxnDispatcher,
};
