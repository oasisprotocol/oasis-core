//! Key manager state in the consensus layer.
use std::collections::HashMap;

use anyhow::anyhow;

use crate::{
    common::{
        crypto::{
            hash::Hash,
            signature::{PublicKey, SignatureBundle},
        },
        key_format::{KeyFormat, KeyFormatAtom},
        namespace::Namespace,
        sgx::EnclaveIdentity,
    },
    consensus::{beacon::EpochTime, state::StateError},
    key_format,
    storage::mkvs::ImmutableMKVS,
};

key_format!(StatusKeyFmt, 0x75, (Hash, u8));

/// Group.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Decode, cbor::Encode)]
#[repr(u8)]
pub enum GroupID {
    // NIST P-384 elliptic curve group.
    #[default]
    NistP384 = 0,
}

/// Consensus CHURP state wrapper.
pub struct ImmutableState<'a, T: ImmutableMKVS> {
    mkvs: &'a T,
}

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Constructs a new ImmutableMKVS.
    pub fn new(mkvs: &'a T) -> ImmutableState<'a, T> {
        ImmutableState { mkvs }
    }
}

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Looks up a specific key manager status by its namespace identifier.
    pub fn status(
        &self,
        runtime_id: Namespace,
        churp_id: u8,
    ) -> Result<Option<Status>, StateError> {
        let h = Hash::digest_bytes(runtime_id.as_ref());
        match self.mkvs.get(&StatusKeyFmt((h, churp_id)).encode()) {
            Ok(Some(b)) => Ok(Some(self.decode_status(&b)?)),
            Ok(None) => Ok(None),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    fn decode_status(&self, data: &[u8]) -> Result<Status, StateError> {
        cbor::from_slice(data).map_err(|err| StateError::Unavailable(anyhow!(err)))
    }
}

/// Status represents the current state of a CHURP instance.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Decode, cbor::Encode)]
pub struct Status {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// GroupID is the identifier of a group used for verifiable secret sharing
    /// and key derivation.
    pub group_id: GroupID,

    /// Threshold is the minimum number of distinct shares required
    /// to reconstruct a key.
    pub threshold: u8,

    /// Round counts the number of handoffs done so far.
    ///
    /// The first round is a special round called the dealer round, in which
    /// nodes do not reshare shares but construct the secret and shares instead.
    pub round: u64,

    /// NextHandoff defines the epoch in which the next handoff will occur.
    ///
    /// If an insufficient number of applications is received, the next handoff
    /// will be delayed by one epoch.
    pub next_handoff: EpochTime,

    /// HandoffInterval is the time interval in epochs between handoffs.
    ///
    /// A zero value disables handoffs.
    pub handoff_interval: EpochTime,

    /// Policy is a signed SGX access control policy.
    pub policy: SignedPolicySGX,

    /// Committee is a vector of nodes holding a share of the secret
    /// in the current round.
    ///
    /// A client needs to obtain at least a threshold number of key shares
    /// from the nodes in this vector to construct the key.
    #[cbor(optional)]
    pub committee: Vec<PublicKey>,

    /// Applications is a map of nodes that wish to form the new committee.
    ///
    /// Candidates are expected to generate a random bivariate polynomial,
    /// construct a verification matrix, compute its checksum, and submit
    /// an application one epoch in advance of the next scheduled handoff.
    /// Subsequently, upon the arrival of the handoff epoch, nodes must execute
    /// the handoff protocol and confirm the reconstruction of its share.
    #[cbor(optional)]
    pub applications: HashMap<PublicKey, Application>,

    /// Checksum is the hash of the merged verification matrix.
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
    /// Checksum is the hash of the random verification matrix.
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

#[cfg(test)]
mod test {
    use std::{collections::HashMap, default::Default, vec};

    use super::*;
    use crate::{
        common::{
            crypto::{
                hash::Hash,
                signature::{Signature, SignatureBundle},
            },
            namespace::Namespace,
            sgx::{EnclaveIdentity, MrEnclave, MrSigner},
        },
        consensus::state::keymanager::churp::PolicySGX,
        storage::mkvs::{
            interop::{Fixture, ProtocolServer},
            Root, RootType, Tree,
        },
    };

    #[test]
    fn test_keymanager_secrets_state_interop() {
        // Keep in sync with go/consensus/cometbft/apps/keymanager/churp/state/interop/interop.go.
        // If mock consensus state changes, update the root hash bellow.
        // See protocol server stdout for hash.
        // To make the hash show up during tests, run "cargo test" as
        // "cargo test -- --nocapture".

        // Setup protocol server with initialized mock consensus state.
        let server = ProtocolServer::new(Fixture::ConsensusMock.into());
        let mock_consensus_root = Root {
            version: 1,
            root_type: RootType::State,
            hash: Hash::from("2e88f31ccb944195b557ca4c2de7589b042696eb5a6cefce925891ccb9da5eed"),
            ..Default::default()
        };
        let mkvs = Tree::builder()
            .with_capacity(100_000, 10_000_000)
            .with_root(mock_consensus_root)
            .build(server.read_sync());
        let state = ImmutableState::new(&mkvs);

        // Prepare expected results.
        let runtime_id =
            Namespace::from("8000000000000000000000000000000000000000000000000000000000000000");
        let enclave1 = EnclaveIdentity {
            mr_enclave: MrEnclave::from(
                "c9a589851b1f35627177fd70378ed778170f737611e4dfbf0b6d25bdff55b474",
            ),
            mr_signer: MrSigner::from(
                "7d310664780931ae103ab30a90171c201af385a72757bb4683578fdebde9adf5",
            ),
        };
        let enclave2 = EnclaveIdentity {
            mr_enclave: MrEnclave::from(
                "756eaf76f5482c5345808b1eaccdd5c60f864bb2aa2d2b870df00ce435af4e23",
            ),
            mr_signer: MrSigner::from(
                "3597a2ff0743016f28e5d7e129304ee1c43dbdae3dba94e19cee3549038a5a32",
            ),
        };
        let signer1 =
            PublicKey::from("96533c123a6f4d33c68357109c2eb7c6e6a0f947be3ae1e320d153f561523ff2");
        let signer2 =
            PublicKey::from("4b97bfd95e829d5838131492b5c133e66ac6ef0db414c0be6207ec78c12d2b17");
        let sig1 = Signature::from("eda666cff6e4030200737e0c7707ad4a378aab4cc0455306992c13da2155b97c91b0fde0325a7a6818f2cbf92813cc587723c8c205a7cb5389ca7b21a038b60a");
        let sig2 = Signature::from("db90d354272e025aa9a5856f32ea4f5d6becb0ff6340f3cb7f9104ac04ef29ed4f9b5c21b7ea82924800b30f94724b40c376414f80780ff8b7b60a34edea9f02");
        let checksum =
            Hash::from("1bff211fae98c88ba82388ae954b88a71d3bbe327e162e9fa711fe7a1b759c3e");
        let committee = vec![signer1, signer2];
        let mut applications = HashMap::new();
        applications.insert(
            signer1,
            Application {
                checksum: checksum.clone(),
                reconstructed: false,
            },
        );
        applications.insert(
            signer2,
            Application {
                checksum: checksum.clone(),
                reconstructed: true,
            },
        );
        let checksum = Some(checksum);

        // Test empty status.
        let status = Status {
            ..Default::default()
        };

        let status = state
            .status(status.runtime_id, status.id)
            .expect("status query should work")
            .expect("status query should return a result");
        assert_eq!(status, status, "invalid status");

        // Test non-empty status.
        let status = Status {
            id: 1,
            runtime_id,
            group_id: GroupID::NistP384,
            threshold: 2,
            round: 3,
            next_handoff: 4,
            handoff_interval: 5,
            policy: SignedPolicySGX {
                policy: PolicySGX {
                    id: 1,
                    runtime_id,
                    serial: 6,
                    may_share: vec![enclave1],
                    may_join: vec![enclave2],
                },
                signatures: vec![
                    SignatureBundle {
                        public_key: signer1,
                        signature: sig1,
                    },
                    SignatureBundle {
                        public_key: signer2,
                        signature: sig2,
                    },
                ],
            },
            committee,
            applications,
            checksum,
        };

        let status = state
            .status(status.runtime_id, status.id)
            .expect("status query should work")
            .expect("status query should return a result");
        assert_eq!(status, status, "invalid status");
    }
}
