//! Ekiden dummy scheduler backend.
extern crate ekiden_beacon_base;
extern crate ekiden_common;
extern crate ekiden_core;
extern crate ekiden_registry_base;
extern crate ekiden_scheduler_base;

#[macro_use]
extern crate log;

#[cfg(not(target_env = "sgx"))]
extern crate rand;

#[cfg(target_env = "sgx")]
extern crate sgx_rand;

mod backend;

pub use backend::DummySchedulerBackend;
