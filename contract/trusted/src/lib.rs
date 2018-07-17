#![feature(use_extern_macros)]

#[macro_use]
extern crate lazy_static;
extern crate serde;
extern crate serde_cbor;
#[cfg(test)]
#[macro_use]
extern crate serde_derive;

extern crate ekiden_common;
extern crate ekiden_contract_common;
extern crate ekiden_enclave_trusted;

pub mod dispatcher;
#[doc(hidden)]
pub mod ecalls;
#[macro_use]
pub mod macros;
