//! Key manager API common types and functions.
use std::sync::{Mutex, Once};

use lazy_static::lazy_static;

use oasis_core_runtime::consensus::keymanager::{PolicySGX, SignedPolicySGX};

#[macro_use]
pub mod api;

// Re-exports.
pub use api::*;

lazy_static! {
    /// Set of trusted policy signers.
    static ref TRUSTED_SIGNERS: Mutex<TrustedPolicySigners> = Mutex::new(TrustedPolicySigners::default());

    /// Initializes the global TRUSTED_SIGNERS only once.
    static ref INIT_TRUSTED_SIGNERS_ONCE: Once = Once::new();
}

/// Set the global set of trusted policy signers.
/// Changing the set of policy signers after the first call is not possible.
pub fn set_trusted_policy_signers(signers: TrustedPolicySigners) -> bool {
    INIT_TRUSTED_SIGNERS_ONCE.call_once(|| {
        *TRUSTED_SIGNERS.lock().unwrap() = signers;
    });

    true
}

/// Verify that policy has valid signatures and that enough of them are from the global set
/// of trusted policy signers.
pub fn verify_policy_and_trusted_signers(
    signed_policy: &SignedPolicySGX,
) -> Result<&PolicySGX, KeyManagerError> {
    TRUSTED_SIGNERS.lock().unwrap().verify(signed_policy)
}
