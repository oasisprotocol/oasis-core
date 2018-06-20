//! Ekiden dummy random beacon backend.
extern crate ekiden_beacon_base;
extern crate ekiden_common;
#[macro_use]
extern crate ekiden_di;
extern crate ekiden_epochtime;

extern crate byteorder;
#[macro_use]
extern crate log;

mod backend;

pub use backend::InsecureDummyRandomBeacon;
