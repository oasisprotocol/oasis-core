//! Ekiden registry clients.
#![feature(try_from)]

extern crate ekiden_common;
extern crate ekiden_registry_api;
extern crate ekiden_registry_base;

extern crate grpcio;

pub mod entity;

pub use entity::*;
