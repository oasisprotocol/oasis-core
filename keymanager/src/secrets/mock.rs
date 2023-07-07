use oasis_core_runtime::{common::namespace::Namespace, consensus::beacon::EpochTime};

use crate::crypto::{kdf::Kdf, Secret, VerifiableSecret, SECRET_SIZE};

use super::SecretProvider;

/// Mock secret provider generates fixed master and ephemeral secrets instead of retrieving them
/// from remote key manager enclaves. Intended for testing purposes only.
pub struct MockSecretProvider {
    runtime_id: Namespace,
    disabled: bool,
}

impl MockSecretProvider {
    /// Create a new mock secret provider.
    ///
    /// The disabled provider does not return any secrets.
    pub fn new(runtime_id: Namespace, disabled: bool) -> Self {
        Self {
            runtime_id,
            disabled,
        }
    }

    /// Get master secret for the given generation.
    pub fn master_secret(&self, generation: u64) -> Secret {
        Secret([generation as u8; SECRET_SIZE])
    }

    /// Get ephemeral secret for the given epoch.
    pub fn ephemeral_secret(&self, epoch: EpochTime) -> Secret {
        Secret([epoch as u8; SECRET_SIZE])
    }

    /// Compute the checksum of the master secret that corresponds to the given generation.
    pub fn checksum_master_secret(&self, generation: u64) -> Vec<u8> {
        let mut checksum = self.runtime_id.0.to_vec();

        for generation in 0..=generation {
            let secret = self.master_secret(generation);
            checksum = Kdf::checksum_master_secret(&secret, &checksum);
        }

        checksum
    }
}

impl SecretProvider for MockSecretProvider {
    fn master_secret_iter(
        &self,
        generation: u64,
    ) -> Box<dyn Iterator<Item = VerifiableSecret> + '_> {
        let secret = self.master_secret(generation);
        let checksum = if generation == 0 {
            self.runtime_id.0.to_vec()
        } else {
            self.checksum_master_secret(generation - 1)
        };
        let mut result = Some(VerifiableSecret { secret, checksum });

        if self.disabled {
            result = None;
        }

        Box::new(std::iter::from_fn(move || result.take()))
    }

    fn ephemeral_secret_iter(&self, epoch: EpochTime) -> Box<dyn Iterator<Item = Secret> + '_> {
        let secret = self.ephemeral_secret(epoch);
        let mut result = Some(secret);

        if self.disabled {
            result = None;
        }

        Box::new(std::iter::from_fn(move || result.take()))
    }
}
