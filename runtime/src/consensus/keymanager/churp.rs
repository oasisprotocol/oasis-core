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

/// Cipher suite identifier.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Decode, cbor::Encode)]
#[repr(u8)]
pub enum SuiteID {
    /// The NIST P-384 elliptic curve group with the SHA3-384 hash function
    /// used to encode arbitrary-length byte strings to elements of the
    /// underlying prime field or elliptic curve points.
    #[default]
    NistP384Sha3_384 = 0,
}

/// Status represents the current state of a CHURP instance.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Decode, cbor::Encode)]
pub struct Status {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// The identifier of a cipher suite used for verifiable secret sharing
    /// and key derivation.
    pub suite_id: SuiteID,

    /// The degree of the secret-sharing polynomial.
    ///
    /// In a (t,n) secret-sharing scheme, where t represents the threshold,
    /// any combination of t+1 or more shares can reconstruct the secret,
    /// while losing n-t or fewer shares still allows the secret to be
    /// recovered.
    pub threshold: u8,

    /// The minimum number of shares that can be lost to render the secret
    /// unrecoverable.
    ///
    /// If t and e represent the threshold and extra shares, respectively,
    /// then the minimum size of the committee is t+e+1.
    pub extra_shares: u8,

    /// The time interval in epochs between handoffs.
    ///
    /// A zero value disables handoffs.
    pub handoff_interval: EpochTime,

    /// A signed SGX access control policy.
    pub policy: SignedPolicySGX,

    /// The epoch of the last successfully completed handoff.
    ///
    /// The zero value indicates that no handoffs have been completed so far.
    /// Note that the first handoff is special and is called the dealer phase,
    /// in which nodes do not reshare or randomize shares but instead construct
    /// the secret and shares.
    pub handoff: EpochTime,

    /// The hash of the verification matrix from the last successfully completed
    /// handoff.
    #[cbor(optional)]
    pub checksum: Option<Hash>,

    /// A vector of nodes holding a share of the secret in the active handoff.
    ///
    /// A client needs to obtain more than a threshold number of key shares
    /// from the nodes in this vector to construct the key.
    #[cbor(optional)]
    pub committee: Vec<PublicKey>,

    /// The epoch in which the next handoff will occur.
    ///
    /// If an insufficient number of applications is received, the next handoff
    /// will be delayed by one epoch.
    pub next_handoff: EpochTime,

    /// The hash of the verification matrix from the current handoff.
    ///
    /// The first candidate to confirm share reconstruction is the source
    /// of truth for the checksum. All other candidates need to confirm
    /// with the same checksum; otherwise, the applications will be annulled,
    /// and the nodes will need to apply for the new committee again.
    #[cbor(optional)]
    pub next_checksum: Option<Hash>,

    /// A map of nodes that wish to form the new committee.
    ///
    /// Candidates are expected to generate a random bivariate polynomial,
    /// construct a verification matrix, compute its checksum, and submit
    /// an application one epoch in advance of the next scheduled handoff.
    /// Subsequently, upon the arrival of the handoff epoch, nodes must execute
    /// the handoff protocol and confirm the reconstruction of its share.
    #[cbor(optional)]
    pub applications: HashMap<PublicKey, Application>,
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
