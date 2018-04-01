//! RPC client backend.

use ekiden_enclave_common::api::IdentityProof;
use sodalite;

pub struct ContractClientCredentials {
    /// The long-term client key.
    pub long_term_private_key: sodalite::BoxSecretKey,
    /// The enclave identity proof of the client for mutual authentication.
    pub identity_proof: IdentityProof,
}

mod base;

#[cfg(not(target_env = "sgx"))]
pub mod web3;

// Re-export.
pub use self::base::ContractClientBackend;

#[cfg(not(target_env = "sgx"))]
pub use self::web3::Web3ContractClientBackend;
