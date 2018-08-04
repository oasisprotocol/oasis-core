#![feature(use_extern_macros)]

extern crate futures_timer;
extern crate grpcio;
#[macro_use]
extern crate log;

extern crate ekiden_beacon_dummy;
extern crate ekiden_registry_dummy;
extern crate ekiden_roothash_dummy;
extern crate ekiden_scheduler_dummy;
extern crate ekiden_storage_dummy;

extern crate ekiden_beacon_api;
extern crate ekiden_beacon_base;
extern crate ekiden_common;
extern crate ekiden_common_api;
extern crate ekiden_core;
extern crate ekiden_di;
extern crate ekiden_epochtime;
extern crate ekiden_instrumentation;
extern crate ekiden_registry_api;
extern crate ekiden_registry_base;
extern crate ekiden_roothash_api;
extern crate ekiden_roothash_base;
extern crate ekiden_scheduler_api;
extern crate ekiden_scheduler_base;
extern crate ekiden_storage_api;
extern crate ekiden_storage_base;

extern crate ekiden_node_dummy_api;

pub mod backend;
pub mod service;
