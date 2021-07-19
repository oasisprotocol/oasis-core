//! Key manager API common types and functions.
use std::{
    collections::HashSet,
    sync::{Mutex, Once},
};

use lazy_static::lazy_static;

use oasis_core_runtime::common::crypto::signature::PublicKey as OasisPublicKey;

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

const POLICY_SIGN_CONTEXT: &'static [u8] = b"oasis-core/keymanager: policy";

impl SignedPolicySGX {
    /// Verify the signatures and return the PolicySGX, if the signatures are correct.
    pub fn verify(&self) -> Result<PolicySGX, KeyManagerError> {
        // Verify the signatures.
        let untrusted_policy_raw = cbor::to_vec(self.policy.clone());
        let mut signers: HashSet<OasisPublicKey> = HashSet::new();
        for sig in &self.signatures {
            let public_key = match sig.public_key {
                Some(public_key) => public_key,
                None => return Err(KeyManagerError::PolicyInvalid),
            };

            if !sig
                .signature
                .verify(&public_key, &POLICY_SIGN_CONTEXT, &untrusted_policy_raw)
                .is_ok()
            {
                return Err(KeyManagerError::PolicyInvalidSignature);
            }
            signers.insert(public_key);
        }

        // Ensure that enough valid signatures from trusted signers are present.
        let trusted_signers = TRUSTED_SIGNERS.lock().unwrap();
        let signers: HashSet<_> = trusted_signers.signers.intersection(&signers).collect();
        let multisig_threshold = match option_env!("OASIS_UNSAFE_KM_POLICY_KEYS") {
            Some(_) => 2,
            None => trusted_signers.threshold,
        };
        if signers.len() < multisig_threshold as usize {
            return Err(KeyManagerError::PolicyInsufficientSignatures);
        }

        Ok(self.policy.clone())
    }
}
