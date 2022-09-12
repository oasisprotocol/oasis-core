use std::collections::HashSet;

use oasis_core_runtime::{
    common::crypto::signature::PublicKey as OasisPublicKey,
    consensus::keymanager::{PolicySGX, SignedPolicySGX},
};

use crate::api::KeyManagerError;

/// Set of trusted key manager policy signing keys.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub struct TrustedPolicySigners {
    /// Set of trusted signers.
    pub signers: HashSet<OasisPublicKey>,
    /// Threshold for determining if enough valid signatures are present.
    pub threshold: u64,
}

impl Default for TrustedPolicySigners {
    fn default() -> Self {
        Self {
            signers: HashSet::new(),
            threshold: 9001,
        }
    }
}

impl TrustedPolicySigners {
    /// Verify that policy has valid signatures and that enough of them are from trusted signers.
    pub fn verify<'a>(
        &self,
        signed_policy: &'a SignedPolicySGX,
    ) -> Result<&'a PolicySGX, KeyManagerError> {
        let policy = signed_policy
            .verify()
            .map_err(|err| KeyManagerError::PolicyInvalid(err.into()))?;

        self.verify_trusted_signers(signed_policy)?;

        Ok(policy)
    }

    /// Verify that policy has enough signatures from trusted signers.
    fn verify_trusted_signers(
        &self,
        signed_policy: &SignedPolicySGX,
    ) -> Result<(), KeyManagerError> {
        // Use set to remove duplicates.
        let all: HashSet<_> = signed_policy
            .signatures
            .iter()
            .map(|s| s.public_key)
            .collect();
        let trusted: HashSet<_> = self.signers.intersection(&all).collect();
        if trusted.len() < self.threshold as usize {
            return Err(KeyManagerError::PolicyInsufficientSignatures);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, iter::FromIterator};

    use crypto::signature::{PublicKey as OasisPublicKey, SignatureBundle};
    use oasis_core_runtime::{common::crypto, consensus::keymanager::SignedPolicySGX};

    use super::TrustedPolicySigners;

    #[test]
    fn test_trusted_policy_signers() {
        // Prepare data for tests.
        let public_keys = vec![
            OasisPublicKey::from(
                "af2c61c73142d1718fb51a7e151680ab4fea5ed0a95108e4e9d6719a6ef6186e",
            ), // trusted
            OasisPublicKey::from(
                "2b87e78e941cccca2222dd30fca04dee45d7e652da907d607b0971422c1bde1f",
            ), // trusted
            OasisPublicKey::from(
                "2c1378defc5a1d932c18c87008e6d33e6fcfed33312fa3224de4e3d7fcc3251c",
            ), // trusted
            OasisPublicKey::from(
                "235ca1d91ed078a3568018bef563edfb3503afa6434dbdee8310ab6fe2df50a7",
            ),
            OasisPublicKey::from(
                "17504048e11cbc8bc164785379f993f1a6934c3a9f10a78b178b59e85cd7c4c4",
            ),
        ];
        let signatures = vec![
            SignatureBundle {
                public_key: public_keys[1], // trusted
                ..Default::default()
            },
            SignatureBundle {
                public_key: public_keys[2], // trusted
                ..Default::default()
            },
            SignatureBundle {
                public_key: public_keys[3],
                ..Default::default()
            },
            SignatureBundle {
                public_key: public_keys[4],
                ..Default::default()
            },
        ];
        let trusted_signers = TrustedPolicySigners {
            signers: HashSet::from_iter(vec![public_keys[0], public_keys[1], public_keys[2]]),
            threshold: 2,
        };

        // Happy path, enough trust (2/3).
        let policy = SignedPolicySGX {
            signatures: signatures[..].to_vec(),
            ..Default::default()
        };
        trusted_signers
            .verify_trusted_signers(&policy)
            .expect("policy should be trusted");

        // Not enough trust (1/3).
        let policy = SignedPolicySGX {
            signatures: signatures[1..].to_vec(),
            ..Default::default()
        };
        trusted_signers
            .verify_trusted_signers(&policy)
            .expect_err("policy should not be trusted");

        // Multiple signatures from the same signer.
        let policy = SignedPolicySGX {
            signatures: vec![
                signatures[0].clone(),
                signatures[0].clone(),
                signatures[0].clone(),
            ],
            ..Default::default()
        };
        trusted_signers
            .verify_trusted_signers(&policy)
            .expect_err("policy should not be trusted");
    }
}
