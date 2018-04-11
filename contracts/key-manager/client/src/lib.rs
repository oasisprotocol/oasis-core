#![feature(use_extern_macros)]

#[macro_use]
extern crate lazy_static;

extern crate ekiden_common;
extern crate ekiden_enclave_common;
extern crate ekiden_key_manager_api;
extern crate ekiden_rpc_client;
extern crate ekiden_rpc_common;
extern crate ekiden_rpc_trusted;

mod client;

pub use client::KeyManager;

/// Helper macro to configure key manager contract identity from a generated file.
///
/// Before a contract can use the key manager client to perform any operations, it
/// needs to configure the identity of the key manager contract that it will be
/// using.
///
/// This can be done by generating an identity of the contract in a build script and
/// then calling this macro to configure this identity with the key manager client.
///
/// The macro takes one argument, a filename of the generated identity file.
#[macro_export]
macro_rules! use_key_manager_contract {
    ($identity:expr) => {
        #[cfg(target_env = "sgx")]
        global_ctors_object! {
            KEY_MANAGER_INIT, key_manager_init = {
                use ekiden_core::bytes::H256;
                use ekiden_trusted::key_manager::KeyManager;

                // Setup the key manager contract identity.
                KeyManager::get().unwrap().set_contract(H256(*include_bytes!($identity)));
            }
        }
    }
}
