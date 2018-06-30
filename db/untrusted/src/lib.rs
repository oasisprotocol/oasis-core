#[macro_use]
extern crate log;
extern crate sgx_types;

extern crate ekiden_common;
extern crate ekiden_enclave_untrusted;
#[macro_use]
extern crate ekiden_instrumentation;
extern crate ekiden_storage_base;

#[doc(hidden)]
pub mod ecall_proxy;
pub mod enclave;
#[doc(hidden)]
pub mod ocall_proxy;

// Exports.
pub use enclave::EnclaveDb;
