extern crate sgx_types;
extern crate sgx_urts;

extern crate base64;
extern crate futures;
extern crate grpcio;
extern crate protobuf;
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_derive;

extern crate ekiden_common;
extern crate ekiden_common_api;
extern crate ekiden_core;
extern crate ekiden_enclave_common;

pub mod ecall_proxy;
pub mod enclave;
pub mod ias;
pub mod ias_proxy;
pub mod identity;

mod generated;

use ekiden_common_api as common;

// Exports.
pub use enclave::Enclave;

// For the below link statements to work, the library paths need to be correctly
// configured. The easiest way to achieve that is to use the build_untrusted
// helper from ekiden_tools.

// Ensure that we link to sgx_urts library.
#[cfg_attr(not(feature = "sgx-simulation"), link(name = "sgx_urts"))]
#[cfg_attr(feature = "sgx-simulation", link(name = "sgx_urts_sim"))]
extern "C" {}
