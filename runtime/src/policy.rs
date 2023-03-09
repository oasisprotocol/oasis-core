//! Consensus SGX and quote policy handling.

use std::sync::Arc;

use anyhow::{bail, Result};
use slog::{debug, Logger};
use thiserror::Error;

use crate::{
    common::{logger::get_logger, namespace::Namespace, sgx::QuotePolicy, version::Version},
    consensus::{
        keymanager::SignedPolicySGX,
        registry::{SGXConstraints, TEEHardware},
        state::{
            beacon::ImmutableState as BeaconState,
            keymanager::{ImmutableState as KeyManagerState, Status},
            registry::ImmutableState as RegistryState,
        },
        verifier::Verifier,
    },
};

/// Policy verifier error.
#[derive(Error, Debug)]
pub enum PolicyVerifierError {
    #[error("missing runtime descriptor")]
    MissingRuntimeDescriptor,
    #[error("no corresponding runtime deployment")]
    NoDeployment,
    #[error("bad TEE constraints")]
    BadTEEConstraints,
    #[error("policy mismatch")]
    PolicyMismatch,
    #[error("policy hasn't been published")]
    PolicyNotPublished,
    #[error("status mismatch")]
    StatusMismatch,
    #[error("status hasn't been published")]
    StatusNotPublished,
    #[error("configured runtime hardware mismatch")]
    HardwareMismatch,
    #[error("runtime doesn't use key manager")]
    NoKeyManager,
}

/// Consensus policy verifier.
pub struct PolicyVerifier {
    consensus_verifier: Arc<dyn Verifier>,
    logger: Logger,
}

impl PolicyVerifier {
    /// Create a new consensus policy verifier.
    pub fn new(consensus_verifier: Arc<dyn Verifier>) -> Self {
        let logger = get_logger("runtime/policy_verifier");
        Self {
            consensus_verifier,
            logger,
        }
    }

    /// Fetch runtime's quote policy from the latest verified consensus layer state.
    ///
    /// If the runtime version is not provided, the policy for the active deployment is returned.
    pub fn quote_policy(
        &self,
        runtime_id: &Namespace,
        version: Option<Version>,
    ) -> Result<QuotePolicy> {
        // Fetch quote policy from the consensus layer using the given or the active version.
        let consensus_state = self.consensus_verifier.latest_state()?;
        let registry_state = RegistryState::new(&consensus_state);
        let runtime = registry_state
            .runtime(runtime_id)?
            .ok_or(PolicyVerifierError::MissingRuntimeDescriptor)?;

        let ad = match version {
            Some(version) => runtime
                .deployment_for_version(version)
                .ok_or(PolicyVerifierError::NoDeployment)?,
            None => {
                let beacon_state = BeaconState::new(&consensus_state);
                let epoch = beacon_state.epoch()?;

                runtime
                    .active_deployment(epoch)
                    .ok_or(PolicyVerifierError::NoDeployment)?
            }
        };

        let policy = match runtime.tee_hardware {
            TEEHardware::TEEHardwareIntelSGX => {
                let sc: SGXConstraints = ad
                    .try_decode_tee()
                    .map_err(|_| PolicyVerifierError::BadTEEConstraints)?;
                sc.policy()
            }
            _ => bail!(PolicyVerifierError::HardwareMismatch),
        };

        Ok(policy)
    }

    /// Verify that runtime's quote policy has been published in the consensus layer.
    pub fn verify_quote_policy(
        &self,
        policy: QuotePolicy,
        runtime_id: &Namespace,
        version: Option<Version>,
    ) -> Result<QuotePolicy> {
        let published_policy = self.quote_policy(runtime_id, version)?;

        if policy != published_policy {
            debug!(
                self.logger,
                "quote policy mismatch";
                "untrusted" => ?policy,
                "published" => ?published_policy,
            );
            return Err(PolicyVerifierError::PolicyMismatch.into());
        }

        Ok(published_policy)
    }

    /// Fetch key manager's status from the latest verified consensus layer state.
    pub fn key_manager_status(&self, key_manager: Namespace) -> Result<Status> {
        let consensus_state = self.consensus_verifier.latest_state()?;
        let km_state = KeyManagerState::new(&consensus_state);
        km_state
            .status(key_manager)?
            .ok_or_else(|| PolicyVerifierError::StatusNotPublished.into())
    }

    /// Verify that key manager's status has been published in the consensus layer.
    pub fn verify_key_manager_status(
        &self,
        status: Status,
        key_manager: Namespace,
    ) -> Result<Status> {
        let published_status = self.key_manager_status(key_manager)?;

        if status != published_status {
            debug!(
                self.logger,
                "key manager status mismatch";
                "untrusted" => ?status,
                "published" => ?published_status,
            );
            return Err(PolicyVerifierError::StatusMismatch.into());
        }

        Ok(published_status)
    }

    /// Fetch key manager's policy from the latest verified consensus layer state.
    pub fn key_manager_policy(&self, key_manager: Namespace) -> Result<SignedPolicySGX> {
        self.key_manager_status(key_manager)?
            .policy
            .ok_or_else(|| PolicyVerifierError::PolicyNotPublished.into())
    }

    /// Verify that key manager's policy has been published in the consensus layer.
    pub fn verify_key_manager_policy(
        &self,
        policy: SignedPolicySGX,
        key_manager: Namespace,
    ) -> Result<SignedPolicySGX> {
        let published_policy = self.key_manager_policy(key_manager)?;

        if policy != published_policy {
            debug!(
                self.logger,
                "key manager policy mismatch";
                "untrusted" => ?policy,
                "published" => ?published_policy,
            );
            return Err(PolicyVerifierError::PolicyMismatch.into());
        }

        Ok(published_policy)
    }

    /// Fetch runtime's key manager.
    pub fn key_manager(&self, runtime_id: &Namespace) -> Result<Namespace> {
        let consensus_state = self.consensus_verifier.latest_state()?;
        let registry_state = RegistryState::new(&consensus_state);
        let runtime = registry_state
            .runtime(runtime_id)?
            .ok_or(PolicyVerifierError::MissingRuntimeDescriptor)?;
        let key_manager = runtime
            .key_manager
            .ok_or(PolicyVerifierError::NoKeyManager)?;

        Ok(key_manager)
    }
}
