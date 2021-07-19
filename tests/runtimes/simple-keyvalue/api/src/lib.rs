// Allow until oasis-core#3572.
#![allow(deprecated)]

#[macro_use]
mod api;

pub use api::{AddEscrow, Key, KeyValue, ReclaimEscrow, Transfer, UpdateRuntime, Withdraw};
