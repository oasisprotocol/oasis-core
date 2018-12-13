#[macro_use]
extern crate lazy_static;

extern crate ekiden_common;
extern crate ekiden_enclave_common;
extern crate ekiden_enclave_logger;
extern crate ekiden_keymanager_api;
extern crate ekiden_keymanager_common;
extern crate ekiden_rpc_client;
extern crate ekiden_rpc_common;
#[cfg(target_env = "sgx")]
extern crate ekiden_rpc_trusted;
extern crate serde;
extern crate serde_cbor;

mod client;

// Reexport
pub use client::KeyManager;
#[cfg(not(target_env = "sgx"))]
pub use client::NetworkRpcClientBackendConfig;

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
        static KM_MRENCLAVE: ekiden_common::bytes::H256 =
            ekiden_common::bytes::H256(*include_bytes!($identity));
        #[cfg(target_env = "sgx")]
        global_ctors_object! {
            KEY_MANAGER_INIT, key_manager_init = {
                use ekiden_core::bytes::H256;
                use ekiden_trusted::key_manager::KeyManager;

                // Setup the key manager contract identity.
                KeyManager::instance().unwrap().set_contract(KM_MRENCLAVE);
            }
        }
    };
}
