//! Key manager state in the consensus layer.
use std::collections::HashMap;

use anyhow::Result;
use thiserror::Error;

use crate::{
    common::{
        crypto::{
            hash::Hash,
            signature::{PublicKey, SignatureBundle},
        },
        namespace::Namespace,
        sgx::EnclaveIdentity,
    },
    consensus::beacon::EpochTime,
};

/// Context used to sign key manager CHURP policies.
const POLICY_SIGNATURE_CONTEXT: &[u8] = b"oasis-core/keymanager/churp: policy";

/// Errors emitted by the CHURP module.
#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid signature")]
    InvalidSignature,
}

/// Group.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Decode, cbor::Encode)]
#[repr(u8)]
pub enum GroupID {
    // NIST P-384 elliptic curve group.
    #[default]
    NistP384 = 0,
}

/// Status represents the current state of a CHURP instance.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Decode, cbor::Encode)]
pub struct Status {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// The identifier of a group used for verifiable secret sharing
    /// and key derivation.
    pub group_id: GroupID,

    /// The minimum number of distinct shares required to reconstruct a key.
    pub threshold: u8,

    /// The epoch of the last successfully executed handoff.
    ///
    /// The zero value indicates that no handoffs have been completed so far.
    /// Note that the first handoff is special and is called the dealer phase,
    /// in which nodes do not reshare or randomize shares but instead construct
    /// the secret and shares.
    pub active_handoff: EpochTime,

    /// The epoch in which the next handoff will occur.
    ///
    /// If an insufficient number of applications is received, the next handoff
    /// will be delayed by one epoch.
    pub next_handoff: EpochTime,

    /// The time interval in epochs between handoffs.
    ///
    /// A zero value disables handoffs.
    pub handoff_interval: EpochTime,

    /// A signed SGX access control policy.
    pub policy: SignedPolicySGX,

    /// A vector of nodes holding a share of the secret in the active handoff.
    ///
    /// A client needs to obtain at least a threshold number of key shares
    /// from the nodes in this vector to construct the key.
    #[cbor(optional)]
    pub committee: Vec<PublicKey>,

    /// A map of nodes that wish to form the new committee.
    ///
    /// Candidates are expected to generate a random bivariate polynomial,
    /// construct a verification matrix, compute its checksum, and submit
    /// an application one epoch in advance of the next scheduled handoff.
    /// Subsequently, upon the arrival of the handoff epoch, nodes must execute
    /// the handoff protocol and confirm the reconstruction of its share.
    #[cbor(optional)]
    pub applications: HashMap<PublicKey, Application>,

    /// The hash of the merged verification matrix.
    ///
    /// The first candidate to confirm share reconstruction is the source
    /// of truth for the checksum. All other candidates need to confirm
    /// with the same checksum; otherwise, the applications will be annulled,
    /// and the nodes will need to apply for the new committee again.
    #[cbor(optional)]
    pub checksum: Option<Hash>,
}

/// Application represents a node's application to form a new committee.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Decode, cbor::Encode)]
pub struct Application {
    /// The hash of the random verification matrix.
    ///
    /// In all handoffs, except in the dealer phase, the verification matrix
    /// needs to be zero-hole.
    pub checksum: Hash,

    /// Reconstructed is true if and only if the node verified all matrices
    /// and successfully reconstructed its share during the handoff.
    pub reconstructed: bool,
}

/// Key manager access control policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct PolicySGX {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// A monotonically increasing policy serial number.
    pub serial: u32,

    /// A vector of enclave identities from which a share can be obtained
    /// during handouts.
    pub may_share: Vec<EnclaveIdentity>,

    /// A vector of enclave identities that may form the new committee
    /// in the next handoffs.
    pub may_join: Vec<EnclaveIdentity>,
}

/// Signed key manager access control policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct SignedPolicySGX {
    /// An SGX access control policy.
    pub policy: PolicySGX,

    /// A vector of signatures.
    #[cbor(optional)]
    pub signatures: Vec<SignatureBundle>,
}

impl SignedPolicySGX {
    /// Verify the signatures.
    pub fn verify(&self) -> Result<&PolicySGX> {
        let raw_policy = cbor::to_vec(self.policy.clone());
        for sig in &self.signatures {
            sig.signature
                .verify(&sig.public_key, POLICY_SIGNATURE_CONTEXT, &raw_policy)
                .map_err(|_| Error::InvalidSignature)?;
        }

        Ok(&self.policy)
    }
}
