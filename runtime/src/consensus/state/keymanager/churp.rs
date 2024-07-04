//! Key manager state in the consensus layer.
use anyhow::anyhow;

use crate::{
    common::{
        crypto::hash::Hash,
        key_format::{KeyFormat, KeyFormatAtom},
        namespace::Namespace,
    },
    consensus::{keymanager::churp::Status, state::StateError},
    key_format,
    storage::mkvs::ImmutableMKVS,
};

key_format!(StatusKeyFmt, 0x75, (Hash, u8));

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

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::*;
    use crate::{
        common::{
            crypto::signature::{PublicKey, Signature, SignatureBundle},
            sgx::{EnclaveIdentity, MrEnclave, MrSigner},
        },
        consensus::keymanager::churp::{Application, PolicySGX, SignedPolicySGX, SuiteId},
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
            hash: Hash::from("8e39bf193f8a954ab8f8d7cb6388c591fd0785ea060bbd8e3752e266b54499d3"),
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
        let next_checksum = checksum;

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
            suite_id: SuiteId::NistP384Sha3_384,
            threshold: 2,
            extra_shares: 1,
            handoff_interval: 3,
            policy: SignedPolicySGX {
                policy: PolicySGX {
                    id: 1,
                    runtime_id,
                    serial: 6,
                    may_share: vec![enclave1],
                    may_join: vec![enclave2],
                    may_query: HashMap::new(),
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
            handoff: 4,
            checksum,
            committee,
            next_handoff: 5,
            next_checksum,
            applications,
        };

        let status = state
            .status(status.runtime_id, status.id)
            .expect("status query should work")
            .expect("status query should return a result");
        assert_eq!(status, status, "invalid status");
    }
}
