extern crate chrono;
extern crate ekiden_common;
extern crate ekiden_common_api;
#[cfg(not(target_env = "sgx"))]
extern crate futures_timer;
#[cfg(not(target_env = "sgx"))]
extern crate grpcio;
#[macro_use]
extern crate ekiden_di;
#[macro_use]
extern crate log;

#[cfg(not(target_env = "sgx"))]
pub mod grpc;
pub mod interface;
pub mod local;
