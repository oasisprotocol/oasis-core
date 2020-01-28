//! Key manager API common types and functions.
extern crate base64;
extern crate failure;
extern crate lazy_static;
extern crate oasis_core_runtime;
extern crate rand;
extern crate rustc_hex;
extern crate serde;
extern crate serde_bytes;
extern crate serde_derive;
extern crate x25519_dalek;

use failure::Fallible;
use lazy_static::lazy_static;
use oasis_core_runtime::common::{cbor, crypto::signature::PublicKey as OasisPublicKey};
use std::{
    collections::HashSet,
    sync::{Mutex, Once},
};

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
    pub fn verify(&self) -> Fallible<PolicySGX> {
        // Verify the signatures.
        let untrusted_policy_raw = cbor::to_vec(&self.policy);
        let mut signers: HashSet<OasisPublicKey> = HashSet::new();
        for sig in &self.signatures {
            let public_key = match sig.public_key {
                Some(public_key) => public_key,
                None => return Err(KeyManagerError::PolicyInvalid.into()),
            };

            if !sig
                .signature
                .verify(&public_key, &POLICY_SIGN_CONTEXT, &untrusted_policy_raw)
                .is_ok()
            {
                return Err(KeyManagerError::PolicyInvalidSignature.into());
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
        if signers.len() < multisig_threshold {
            return Err(KeyManagerError::PolicyInsufficientSignatures.into());
        }

        Ok(self.policy.clone())
    }
}
