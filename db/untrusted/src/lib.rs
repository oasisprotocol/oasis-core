#[macro_use]
extern crate log;
extern crate sgx_types;

extern crate ekiden_common;
extern crate ekiden_enclave_untrusted;
extern crate ekiden_storage_base;

pub mod enclave;
#[doc(hidden)]
pub mod ecall_proxy;
#[doc(hidden)]
pub mod ocall_proxy;

// Exports.
pub use enclave::EnclaveDb;
