#[cfg(target_env = "sgx")]
extern crate sgx_trts;
#[cfg(target_env = "sgx")]
extern crate sgx_tse;
#[cfg(target_env = "sgx")]
extern crate sgx_tseal;
extern crate sgx_types;

#[macro_use]
extern crate lazy_static;
extern crate protobuf;
extern crate serde;
extern crate serde_cbor;
extern crate sodalite;

extern crate ekiden_common;
extern crate ekiden_enclave_common;

pub mod capabilitytee;
pub mod crypto;
pub mod enclave;
pub mod identity;
pub mod utils;

/// Declare enclave initialization structures.
///
/// **This macro must be used in each enclave in order for the initialization
/// handlers of other modules to work correctly.***
#[macro_export]
macro_rules! enclave_init {
    () => {
        #[doc(hidden)]
        #[no_mangle]
        pub extern "C" fn __ekiden_enclave() {
            // We define a symbol called __ekiden_enclave, which is forced to be
            // used by the linker script. Without this, the .init_array section
            // of the resulting library is removed by the linker and thus no
            // initialization is done.
        }
    };
}
