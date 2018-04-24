extern crate protobuf;
extern crate sgx_types;
extern crate sgx_urts;

#[macro_use]
extern crate lazy_static;
extern crate serde;
extern crate serde_cbor;

extern crate ekiden_common;
extern crate ekiden_enclave_untrusted;
extern crate ekiden_rpc_common;

pub mod enclave;
#[doc(hidden)]
pub mod ocall_proxy;
#[doc(hidden)]
pub mod ecall_proxy;

#[macro_use]
pub mod router;

// Exports.
pub use enclave::EnclaveRpc;

// For the below link statements to work, the library paths need to be correctly
// configured. The easiest way to achieve that is to use the build_untrusted
// helper from ekiden_tools.

// Ensure that we link to sgx_urts library.
#[cfg_attr(not(feature = "sgx-simulation"), link(name = "sgx_urts"))]
#[cfg_attr(feature = "sgx-simulation", link(name = "sgx_urts_sim"))]
// Ensure that we link to sgx_uae_service library.
#[cfg_attr(not(feature = "sgx-simulation"), link(name = "sgx_uae_service"))]
#[cfg_attr(feature = "sgx-simulation", link(name = "sgx_uae_service_sim"))]
extern "C" {}
