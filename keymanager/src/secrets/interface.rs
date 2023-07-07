use oasis_core_runtime::consensus::beacon::EpochTime;

use crate::crypto::{Secret, VerifiableSecret};

/// Interface for providing master and ephemeral secrets.
pub trait SecretProvider {
    /// Returns an iterator that provides access to all the replicas of the master secret
    /// for the given generation.
    fn master_secret_iter(
        &self,
        generation: u64,
    ) -> Box<dyn Iterator<Item = VerifiableSecret> + '_>;

    /// Returns an iterator that provides access to all the replicas of the ephemeral secret
    /// for the given epoch.
    fn ephemeral_secret_iter(&self, epoch: EpochTime) -> Box<dyn Iterator<Item = Secret> + '_>;
}
