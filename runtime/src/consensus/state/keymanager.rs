//! Key manager state in the consensus layer.
use anyhow::anyhow;

use crate::{
    common::{
        crypto::{hash::Hash, signature::PublicKey},
        key_format::{KeyFormat, KeyFormatAtom},
        namespace::Namespace,
    },
    consensus::{
        beacon::EpochTime,
        keymanager::{
            SignedEncryptedEphemeralSecret, SignedEncryptedMasterSecret, SignedPolicySGX,
        },
        state::StateError,
    },
    key_format,
    storage::mkvs::ImmutableMKVS,
};

/// Consensus key manager state wrapper.
pub struct ImmutableState<'a, T: ImmutableMKVS> {
    mkvs: &'a T,
}

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Constructs a new ImmutableMKVS.
    pub fn new(mkvs: &'a T) -> ImmutableState<'a, T> {
        ImmutableState { mkvs }
    }
}

key_format!(StatusKeyFmt, 0x70, Hash);
key_format!(MasterSecretKeyFmt, 0x72, Hash);
key_format!(EphemeralSecretKeyFmt, 0x73, Hash);

/// Current key manager status.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Decode, cbor::Encode)]
pub struct Status {
    /// Runtime ID of the key manager.
    pub id: Namespace,
    /// True iff the key manager is done initializing.
    pub is_initialized: bool,
    /// True iff the key manager is secure.
    pub is_secure: bool,
    /// Generation of the latest master secret.
    pub generation: u64,
    /// Epoch of the last master secret rotation.
    pub rotation_epoch: EpochTime,
    /// Key manager master secret verification checksum.
    pub checksum: Vec<u8>,
    /// List of currently active key manager node IDs.
    pub nodes: Vec<PublicKey>,
    /// Key manager policy.
    pub policy: Option<SignedPolicySGX>,
    /// Runtime signing key of the key manager.
    pub rsk: Option<PublicKey>,
}

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Looks up a specific key manager status by its namespace identifier.
    pub fn status(&self, id: Namespace) -> Result<Option<Status>, StateError> {
        let h = Hash::digest_bytes(id.as_ref());
        match self.mkvs.get(&StatusKeyFmt(h).encode()) {
            Ok(Some(b)) => Ok(Some(self.decode_status(&b)?)),
            Ok(None) => Ok(None),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    /// Returns the list of all key manager statuses.
    pub fn statuses(&self) -> Result<Vec<Status>, StateError> {
        let mut it = self.mkvs.iter();
        it.seek(&StatusKeyFmt::default().encode_partial(0));

        let mut result: Vec<Status> = Vec::new();

        while let Some(value) = it
            .next()
            .and_then(|(key, value)| StatusKeyFmt::decode(&key).map(|_| value))
        {
            result.push(self.decode_status(&value)?)
        }

        Ok(result)
    }

    /// Looks up a specific key manager master secret by its namespace identifier.
    pub fn master_secret(
        &self,
        id: Namespace,
    ) -> Result<Option<SignedEncryptedMasterSecret>, StateError> {
        let h = Hash::digest_bytes(id.as_ref());
        match self.mkvs.get(&MasterSecretKeyFmt(h).encode()) {
            Ok(Some(b)) => Ok(Some(self.decode_master_secret(&b)?)),
            Ok(None) => Ok(None),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    /// Looks up a specific key manager ephemeral secret by its namespace identifier and epoch.
    pub fn ephemeral_secret(
        &self,
        id: Namespace,
    ) -> Result<Option<SignedEncryptedEphemeralSecret>, StateError> {
        let h = Hash::digest_bytes(id.as_ref());
        match self.mkvs.get(&EphemeralSecretKeyFmt(h).encode()) {
            Ok(Some(b)) => Ok(Some(self.decode_ephemeral_secret(&b)?)),
            Ok(None) => Ok(None),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    fn decode_status(&self, data: &[u8]) -> Result<Status, StateError> {
        cbor::from_slice(data).map_err(|err| StateError::Unavailable(anyhow!(err)))
    }

    fn decode_master_secret(&self, data: &[u8]) -> Result<SignedEncryptedMasterSecret, StateError> {
        cbor::from_slice(data).map_err(|err| StateError::Unavailable(anyhow!(err)))
    }

    fn decode_ephemeral_secret(
        &self,
        data: &[u8],
    ) -> Result<SignedEncryptedEphemeralSecret, StateError> {
        cbor::from_slice(data).map_err(|err| StateError::Unavailable(anyhow!(err)))
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, default::Default, vec};

    use rustc_hex::FromHex;

    use super::*;
    use crate::{
        common::{
            crypto::{
                hash::Hash,
                signature::{Signature, SignatureBundle},
                x25519,
            },
            namespace::Namespace,
            sgx::{EnclaveIdentity, MrEnclave, MrSigner},
        },
        consensus::keymanager::{
            EnclavePolicySGX, EncryptedEphemeralSecret, EncryptedSecret, PolicySGX,
        },
        storage::mkvs::{
            interop::{Fixture, ProtocolServer},
            Root, RootType, Tree,
        },
    };

    #[test]
    fn test_keymanager_state_interop() {
        // Keep in sync with go/consensus/tendermint/apps/keymanager/state/interop/interop.go.
        // If mock consensus state changes, update the root hash bellow.
        // See protocol server stdout for hash.
        // To make the hash show up during tests, run "cargo test" as
        // "cargo test -- --nocapture".

        // Setup protocol server with initialized mock consensus state.
        let server = ProtocolServer::new(Fixture::ConsensusMock.into());
        let mock_consensus_root = Root {
            version: 1,
            root_type: RootType::State,
            hash: Hash::from("a40448052f74a1c0c2d47c2b01a433ad7f3782ea47dfe5575170fec2587569c9"),
            ..Default::default()
        };
        let mkvs = Tree::builder()
            .with_capacity(100_000, 10_000_000)
            .with_root(mock_consensus_root)
            .build(server.read_sync());
        let keymanager_state = ImmutableState::new(&mkvs);

        // Prepare expected results.
        let runtime =
            Namespace::from("8000000000000000000000000000000000000000000000000000000000000000");
        let keymanager1 =
            Namespace::from("c000000000000000fffffffffffffffffffffffffffffffffffffffffffffffe");
        let keymanager2 =
            Namespace::from("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff");
        let runtime_enclave = EnclaveIdentity {
            mr_enclave: MrEnclave::from(
                "18256f783c071521be2da041cd9347b5bdb5a8ef58fb34658571a6e14cf1fcb0",
            ),
            mr_signer: MrSigner::from(
                "e48049d1de0eb333523991671a6c93b97dd65bcf09273d5b6bfe8262dc968ec7",
            ),
        };
        let keymanager_enclave1 = EnclaveIdentity {
            mr_enclave: MrEnclave::from(
                "c9a589851b1f35627177fd70378ed778170f737611e4dfbf0b6d25bdff55b474",
            ),
            mr_signer: MrSigner::from(
                "7d310664780931ae103ab30a90171c201af385a72757bb4683578fdebde9adf5",
            ),
        };
        let keymanager_enclave2 = EnclaveIdentity {
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
        let checksum = "1bff211fae98c88ba82388ae954b88a71d3bbe327e162e9fa711fe7a1b759c3e"
            .from_hex()
            .unwrap();

        let expected_statuses = vec![
            Status {
                id: keymanager1,
                is_initialized: false,
                is_secure: false,
                generation: 0,
                rotation_epoch: 0,
                checksum: vec![],
                nodes: vec![],
                policy: None,
                rsk: None,
            },
            Status {
                id: keymanager2,
                is_initialized: true,
                is_secure: true,
                generation: 0,
                rotation_epoch: 0,
                checksum: checksum,
                nodes: vec![signer1, signer2],
                policy: Some(SignedPolicySGX {
                    policy: PolicySGX {
                        serial: 1,
                        id: keymanager2,
                        enclaves: HashMap::from([(
                            keymanager_enclave1,
                            EnclavePolicySGX {
                                may_query: HashMap::from([(runtime, vec![runtime_enclave])]),
                                may_replicate: vec![keymanager_enclave2],
                            },
                        )]),
                        master_secret_rotation_interval: 0,
                        max_ephemeral_secret_age: 10,
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
                }),
                rsk: None,
            },
        ];

        let rek1 = x25519::PrivateKey::from_test_seed("first rek".to_string());
        let rek2 = x25519::PrivateKey::from_test_seed("second rek".to_string());

        let expected_secret = SignedEncryptedEphemeralSecret {
            secret: EncryptedEphemeralSecret {
                runtime_id: keymanager1,
                epoch: 1,
                secret: EncryptedSecret{
                    checksum: vec![1,2,3,4,5],
                    pub_key: rek1.public_key(),
                    ciphertexts: HashMap::from([
                        (rek1.public_key(), vec![1, 2, 3]),
                        (rek2.public_key(), vec![4, 5, 6]),
                    ]),
                },
            },
            signature: Signature::from("4a2d098e02411fdc14d6a36f91bb362fd4f4dbaadb4cbf70e20e038fe1740bc7dde0b20afd25657d6abc916be2b9ed0054d586aedb2b7951c99aab3206b24b02"),
        };

        // Test statuses.
        let mut statuses = keymanager_state
            .statuses()
            .expect("statuses query should work");
        statuses.sort_by(|a, b| a.id.partial_cmp(&b.id).unwrap());
        assert_eq!(statuses, expected_statuses, "invalid statuses");

        // Test status.
        let status = keymanager_state
            .status(expected_statuses[1].id)
            .expect("status query should work")
            .expect("status query should return a result");
        assert_eq!(status, expected_statuses[1], "invalid status");

        let id =
            Namespace::from("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let status = keymanager_state
            .status(id)
            .expect("status query should work");
        assert_eq!(status, None, "invalid status");

        // Test ephemeral secret (happy path, invalid epoch, invalid runtime).
        let secret = keymanager_state
            .ephemeral_secret(keymanager1)
            .expect("ephemeral secret query should work")
            .expect("ephemeral secret query should return a result");
        assert_eq!(secret, expected_secret, "invalid ephemeral secret");
    }
}
