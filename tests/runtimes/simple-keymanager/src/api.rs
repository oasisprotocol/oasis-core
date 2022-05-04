#[cfg(target_env = "sgx")]
use std::collections::HashSet;

use oasis_core_keymanager_api_common::*;
#[cfg(target_env = "sgx")]
use oasis_core_runtime::common::crypto::signature::PrivateKey as OasisPrivateKey;

#[cfg(target_env = "sgx")]
pub fn trusted_policy_signers() -> TrustedPolicySigners {
    TrustedPolicySigners {
        signers: {
            let mut set = HashSet::new();
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
            set
        },
        threshold: 2,
    }
}

#[cfg(not(target_env = "sgx"))]
pub fn trusted_policy_signers() -> TrustedPolicySigners {
    TrustedPolicySigners::default()
}
