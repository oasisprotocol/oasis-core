//! Key manager API.
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
use std::collections::HashSet;

use oasis_core_runtime::common::{
    cbor,
    crypto::signature::{PrivateKey as OasisPrivateKey, PublicKey as OasisPublicKey},
};

#[macro_use]
mod api;

// Re-exports.
pub use api::*;

lazy_static! {
    static ref MULTISIG_KEYS: HashSet<OasisPublicKey> = {
        let mut set = HashSet::new();
        if option_env!("OASIS_UNSAFE_KM_POLICY_KEYS").is_some() {
            for seed in [
                "ekiden key manager test multisig key 0",
                "ekiden key manager test multisig key 1",
                "ekiden key manager test multisig key 2",
            ].iter() {
                let private_key = OasisPrivateKey::from_test_seed(
                    seed.to_string(),
                );
                set.insert(private_key.public_key());
            }
        }

        // TODO: Populate with the production keys as well.
        set
    };
}
const MULTISIG_THRESHOLD: usize = 9001; // TODO: Set this to a real value.

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
        let signers: HashSet<_> = MULTISIG_KEYS.intersection(&signers).collect();
        let multisig_threshold = match option_env!("OASIS_UNSAFE_KM_POLICY_KEYS") {
            Some(_) => 2,
            None => MULTISIG_THRESHOLD,
        };
        if signers.len() < multisig_threshold {
            return Err(KeyManagerError::PolicyInsufficientSignatures.into());
        }

        Ok(self.policy.clone())
    }
}
