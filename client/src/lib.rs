//! Oasis Core client library.
extern crate futures;
#[cfg(not(target_env = "sgx"))]
extern crate grpcio;
extern crate oasis_core_runtime;
#[cfg(not(target_env = "sgx"))]
extern crate rustracing;
#[cfg(not(target_env = "sgx"))]
extern crate rustracing_jaeger;
extern crate serde;
extern crate serde_bytes;
extern crate serde_derive;
#[macro_use]
extern crate failure;
extern crate io_context;
#[cfg(not(target_env = "sgx"))]
extern crate tokio;
extern crate tokio_current_thread;
extern crate tokio_executor;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
pub mod grpc;
#[cfg(not(target_env = "sgx"))]
pub mod node;
// TODO: Rename "rpc" module to "enclave_rpc" or similar.
pub mod rpc;
#[cfg(not(target_env = "sgx"))]
pub mod transaction;

/// Boxed future type.
pub type BoxFuture<T> = Box<dyn futures::Future<Item = T, Error = failure::Error> + Send>;

// Re-exports.
pub use self::rpc::RpcClient;
#[cfg(not(target_env = "sgx"))]
pub use self::{node::Node, transaction::TxnClient};
