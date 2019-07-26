//! Ekiden runtime SDK.
//!
//! # Examples
//!
//! To create a minimal runtime that doesn't expose any APIs to the
//! outside world, you need to call the `start_runtime` function:
//! ```rust,ignore
//! ekiden_runtime::start_runtime(Some(Box::new(reg)));
//! ```
//!
//! This will start the required services needed to communicate with
//! the worker host.
#![feature(test)]
#![feature(box_into_pin)]
#![feature(pin_into_inner)]
#![feature(const_vec_new)]

#[macro_use]
extern crate slog;
extern crate crossbeam;
extern crate lazy_static;
extern crate serde_bytes;
extern crate serde_cbor;
extern crate serde_derive;
extern crate serde_json;
extern crate slog_json;
extern crate slog_scope;
extern crate slog_stdlog;
#[macro_use]
extern crate failure;
extern crate base64;
extern crate bincode;
extern crate chrono;
#[macro_use]
extern crate intrusive_collections;
extern crate io_context;
extern crate pem_iterator;
extern crate percent_encoding;
extern crate ring;
extern crate rustc_hex;
extern crate snow;
extern crate tokio_current_thread;
extern crate tokio_executor;
extern crate webpki;

use lazy_static::lazy_static;
#[cfg(target_env = "sgx")]
use sgx_isa::{AttributesFlags, Report};

#[macro_use]
pub mod common;
pub mod dispatcher;
pub mod executor;
pub mod init;
pub mod macros;
pub mod protocol;
pub mod rak;
pub mod rpc;
pub mod storage;
pub mod tracing;
pub mod transaction;
pub mod types;

use crate::common::version::{Version, PROTOCOL_VERSION};

#[cfg(target_env = "sgx")]
use self::common::sgx::avr::{EnclaveIdentity, MrSigner};

lazy_static! {
    pub static ref BUILD_INFO: BuildInfo = {
        // Non-SGX builds are insecure by definition.
        #[cfg(not(target_env = "sgx"))]
        let is_secure = false;

        // SGX build security depends on how it was built.
        #[cfg(target_env = "sgx")]
        let is_secure = {
            // Optimistically start out as "it could be secure", and any single
            // insecure build time option will propagate failure.
            let maybe_secure = true;

            // AVR signature verification MUST be enabled.
            let maybe_secure = maybe_secure & option_env!("EKIDEN_UNSAFE_SKIP_AVR_VERIFY").is_none();

            // IAS `GROUP_OUT_OF_DATE` and `CONFIGRUATION_NEEDED` responses
            // MUST count as IAS failure.
            //
            // Rationale: This is how IAS signifies that the host environment
            // is insecure (eg: SMT is enabled when it should not be).
            let maybe_secure = maybe_secure & option_env!("EKIDEN_STRICT_AVR_VERIFY").is_some();

            // The enclave MUST NOT be a debug one.
            let maybe_secure = maybe_secure & !Report::for_self().attributes.flags.contains(AttributesFlags::DEBUG);

            // The enclave MUST NOT be signed by a test key,
            let enclave_identity = EnclaveIdentity::current().unwrap();
            let fortanix_mrsigner = MrSigner::from("9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a");
            let maybe_secure = maybe_secure & (enclave_identity.mr_signer != fortanix_mrsigner);

            maybe_secure
        };

        BuildInfo {
            protocol_version: PROTOCOL_VERSION,
            is_secure,
        }
    };
}

/// Runtime build information.
pub struct BuildInfo {
    /// Supported runtime protocol version.
    pub protocol_version: Version,
    /// True iff the build can provide integrity and confidentiality.
    pub is_secure: bool,
}

// Re-exports.
pub use self::{
    init::start_runtime,
    protocol::Protocol,
    rpc::{demux::Demux as RpcDemux, dispatcher::Dispatcher as RpcDispatcher},
    transaction::dispatcher::Dispatcher as TxnDispatcher,
};
