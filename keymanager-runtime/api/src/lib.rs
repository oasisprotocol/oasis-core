use std::collections::HashSet;

use oasis_core_runtime::common::crypto::signature::PrivateKey as OasisPrivateKey;

#[macro_use]
mod api;

// Re-exports.
pub use api::*;
pub use oasis_core_keymanager_api_common::*;

/// Initializes the set of trusted policy signers for this key manager.
pub fn init_trusted_policy_signers() {
    set_trusted_policy_signers(TrustedPolicySigners {
        signers: {
            let mut set = HashSet::new();
            if option_env!("OASIS_UNSAFE_KM_POLICY_KEYS").is_some() {
                for seed in [
                    "ekiden key manager test multisig key 0",
                    "ekiden key manager test multisig key 1",
                    "ekiden key manager test multisig key 2",
                ]
                .iter()
                {
                    let private_key = OasisPrivateKey::from_test_seed(seed.to_string());
                    set.insert(private_key.public_key());
                }
            }

            // TODO: Populate with the production keys as well.
            set
        },
        threshold: 9001, // TODO: Set this to a real value.
    });
}
