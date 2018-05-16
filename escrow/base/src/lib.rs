#![feature(try_from)]

//! Ekiden Stake Escrow interface.
extern crate byteorder;
extern crate ekiden_common;
extern crate ekiden_stake_api;
extern crate grpcio;
extern crate protobuf;

pub mod stake_backend;
pub mod stake_service;
// pub mod test;

pub use stake_backend::*;
pub use stake_service::*;
