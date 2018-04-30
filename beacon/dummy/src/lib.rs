//! Ekiden dummy random beacon backend.
extern crate byteorder;
extern crate ekiden_beacon_base;
extern crate ekiden_common;

mod backend;

pub use backend::InsecureDummyRandomBeacon;
