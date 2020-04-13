use oasis_core_keymanager_api_common::*;
use oasis_core_runtime::common::crypto::signature::PrivateKey as OasisPrivateKey;
use std::collections::HashSet;

pub fn trusted_policy_signers() -> TrustedPolicySigners {
    TrustedPolicySigners {
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
    }
}
