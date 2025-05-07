//! Oasis Core runtime SDK.
//!
//! # Examples
//!
//! To create a minimal runtime that doesn't expose any APIs to the
//! outside world, you need to call the `start_runtime` function:
//! ```rust,ignore
//! oasis_core_runtime::start_runtime(Some(Box::new(reg)), config);
//! ```
//!
//! This will start the required services needed to communicate with
//! the worker host.
#![feature(test)]
#![feature(arbitrary_self_types)]

use lazy_static::lazy_static;
#[cfg(target_env = "sgx")]
use sgx_isa::{AttributesFlags, Report};

#[cfg_attr(test, macro_use)]
extern crate base64_serde;

#[macro_use]
pub mod common;
pub mod app;
mod attestation;
pub mod cache;
pub mod config;
pub mod consensus;
pub mod dispatcher;
pub mod enclave_rpc;
pub mod future;
pub mod host;
pub mod identity;
pub mod init;
pub mod policy;
pub mod protocol;
pub mod storage;
pub mod transaction;
pub mod types;

use common::{
    sgx::{EnclaveIdentity, MrSigner},
    version::{Version, PROTOCOL_VERSION},
};

// Validate features.
#[cfg(all(target_env = "sgx", feature = "debug-mock-sgx"))]
compile_error!("the debug-mock-sgx feature can only be enabled on non-sgx targets");

#[cfg(all(target_env = "sgx", feature = "tdx"))]
compile_error!("the tdx feature can only be enabled on non-sgx targets");

#[cfg(all(feature = "tdx", feature = "debug-mock-sgx"))]
compile_error!("the tdx feature can't be enabled together with debug-mock-sgx");

lazy_static! {
    pub static ref BUILD_INFO: BuildInfo = {
        // Determine TEE type.
        let tee_type = if cfg!(any(target_env = "sgx", feature = "debug-mock-sgx")) {
            TeeType::Sgx
        } else if cfg!(feature = "tdx") {
            TeeType::Tdx
        } else {
            TeeType::None
        };

        // Determine build security.
        #[allow(clippy::let_and_return)]
        let is_secure = match tee_type {
            TeeType::Sgx => {
                // SGX build security depends on how it was built.
                //
                // Optimistically start out as "it could be secure", and any single insecure build time
                // option will propagate failure.
                let maybe_secure = true;

                // Quote signature verification MUST be enabled.
                let maybe_secure = maybe_secure && option_env!("OASIS_UNSAFE_SKIP_AVR_VERIFY").is_none();

                // Disallow debug enclaves MUST be enabled.
                let maybe_secure = maybe_secure && option_env!("OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES").is_none();

                // Attestation `OutOfDate` and `ConfigurationNeeded` responses MUST count as attestation
                // failure.
                //
                // Rationale: This is how remote attestation signifies that the host environment is
                // insecure (eg: SMT is enabled when it should not be).
                let maybe_secure = maybe_secure && option_env!("OASIS_UNSAFE_LAX_AVR_VERIFY").is_none();

                // The enclave MUST NOT be a debug one.
                #[cfg(target_env = "sgx")]
                let maybe_secure = maybe_secure && !Report::for_self().attributes.flags.contains(AttributesFlags::DEBUG);

                // The enclave MUST NOT be signed by a test key,
                let enclave_identity = EnclaveIdentity::current().unwrap();
                let fortanix_mrsigner = MrSigner::from("9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a");
                let maybe_secure = maybe_secure && (enclave_identity.mr_signer != fortanix_mrsigner);

                maybe_secure
            }
            TeeType::Tdx => {
                // TDX build security depends on how it was built.
                //
                // Optimistically start out as "it could be secure", and any single insecure build time
                // option will propagate failure.
                let maybe_secure = true;

                // Quote signature verification MUST be enabled.
                let maybe_secure = maybe_secure && option_env!("OASIS_UNSAFE_SKIP_AVR_VERIFY").is_none();

                // Disallow debug enclaves MUST be enabled.
                let maybe_secure = maybe_secure && option_env!("OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES").is_none();

                // Attestation `OutOfDate` and `ConfigurationNeeded` responses MUST count as attestation
                // failure.
                //
                // Rationale: This is how remote attestation signifies that the host environment is
                // insecure (eg: SMT is enabled when it should not be).
                let maybe_secure = maybe_secure && option_env!("OASIS_UNSAFE_LAX_AVR_VERIFY").is_none();

                // TODO: Debug TD attributes.

                maybe_secure
            }
            TeeType::None => {
                // Non-TEE builds are insecure by definition.
                false
            }
        };

        BuildInfo {
            tee_type,
            protocol_version: PROTOCOL_VERSION,
            is_secure,
        }
    };
}

/// TEE type this build is for.
#[derive(Debug, Default, PartialEq, Eq)]
pub enum TeeType {
    #[default]
    None,
    Sgx,
    Tdx,
}

/// Runtime build information.
#[derive(Debug)]
pub struct BuildInfo {
    /// TEE type this build is for.
    pub tee_type: TeeType,
    /// Supported runtime protocol version.
    pub protocol_version: Version,
    /// True iff the build can provide integrity and confidentiality.
    pub is_secure: bool,
}

// Re-exports.
pub use self::{
    enclave_rpc::{demux::Demux as RpcDemux, dispatcher::Dispatcher as RpcDispatcher},
    init::start_runtime,
    protocol::Protocol,
    transaction::dispatcher::Dispatcher as TxnDispatcher,
};

// Re-export the cbor crate.
pub use cbor;
