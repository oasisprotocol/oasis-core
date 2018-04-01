#![feature(use_extern_macros)]

extern crate protobuf;

#[macro_use]
extern crate ekiden_core;

#[macro_use]
mod api;
mod generated;

pub use generated::api::*;
