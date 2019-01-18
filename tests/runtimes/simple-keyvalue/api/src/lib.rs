extern crate serde;
#[macro_use]
extern crate serde_derive;

extern crate ekiden_core;
extern crate ekiden_trusted;

#[macro_use]
mod api;

pub use api::KeyValue;
