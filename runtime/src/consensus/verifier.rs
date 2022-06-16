//! Trait for consensus layer verification.
use thiserror::Error;

use super::{
    beacon::EpochTime,
    roothash::{ComputeResultsHeader, Header},
    state::ConsensusState,
    LightBlock,
};
use crate::{common::namespace::Namespace, types};

#[derive(Debug, Error)]
pub enum Error {
    #[error("builder: {0}")]
    Builder(#[source] anyhow::Error),

    #[error("verification: {0}")]
    VerificationFailed(#[source] anyhow::Error),

    #[error("trust root loading failed")]
    TrustRootLoadingFailed,

    #[error("internal error")]
    Internal,
}

impl From<Error> for types::Error {
    fn from(e: Error) -> Self {
        Self {
            module: "verifier".to_string(),
            code: 1,
            message: e.to_string(),
        }
    }
}

/// Verifier is the consensus layer state verifier trait.
pub trait Verifier: Send + Sync {
    /// Synchronize the verifier state up to including the passed consensus height.
    fn sync(&self, height: u64) -> Result<(), Error>;

    /// Verify that the given runtime header is valid at the given consensus layer block and return
    /// the consensus layer state accessor for that block.
    fn verify(
        &self,
        consensus_block: LightBlock,
        runtime_header: Header,
        epoch: EpochTime,
    ) -> Result<ConsensusState, Error>;

    /// Verify that the given runtime header is valid at the given consensus layer block and return
    /// the consensus layer state accessor for that block.
    ///
    /// This is a relaxed version of the `verify` function that should be used for verifying state
    /// in queries.
    fn verify_for_query(
        &self,
        consensus_block: LightBlock,
        runtime_header: Header,
        epoch: EpochTime,
    ) -> Result<ConsensusState, Error>;

    /// Return the consensus layer state accessor for the given consensus layer block WITHOUT
    /// performing any verification. This method should only be used for operations that do not
    /// require integrity guarantees.
    fn unverified_state(&self, consensus_block: LightBlock) -> Result<ConsensusState, Error>;

    /// Return the latest verified consensus layer state.
    fn latest_state(&self) -> Result<ConsensusState, Error>;

    /// Record the given (locally computed and thus verified) results header as trusted.
    fn trust(&self, header: &ComputeResultsHeader) -> Result<(), Error>;
}

/// Consensus layer trust root.
#[derive(Debug, Clone, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct TrustRoot {
    /// Known trusted height.
    pub height: u64,
    /// Known hex-encoded trusted consensus layer header hash.
    pub hash: String,
    /// Known runtime identifier.
    pub runtime_id: Namespace,
}
