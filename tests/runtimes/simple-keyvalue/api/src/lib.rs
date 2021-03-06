// Allow until oasis-core#3572.
#![allow(deprecated)]

extern crate serde;

extern crate oasis_core_runtime;

#[macro_use]
mod api;

pub use api::{AddEscrow, Key, KeyValue, ReclaimEscrow, Transfer, UpdateRuntime, Withdraw};
