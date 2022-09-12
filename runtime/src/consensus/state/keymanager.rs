//! Key manager state in the consensus layer.
use anyhow::anyhow;
use io_context::Context;

use crate::{
    common::{
        crypto::{hash::Hash, signature::PublicKey},
        key_format::{KeyFormat, KeyFormatAtom},
        namespace::Namespace,
    },
    consensus::{keymanager::SignedPolicySGX, state::StateError},
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

/// Current key manager status.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Decode, cbor::Encode)]
pub struct Status {
    /// Runtime ID of the key manager.
    pub id: Namespace,
    /// True iff the key manager is done initializing.
    pub is_initialized: bool,
    /// True iff the key manager is secure.
    pub is_secure: bool,
    /// Key manager master secret verification checksum.
    pub checksum: Vec<u8>,
    /// List of currently active key manager node IDs.
    pub nodes: Vec<PublicKey>,
    /// Key manager policy.
    pub policy: Option<SignedPolicySGX>,
}

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Looks up a specific key manager status by its namespace identifier.
    pub fn status(&self, ctx: Context, id: Namespace) -> Result<Option<Status>, StateError> {
        let h = Hash::digest_bytes(id.as_ref());
        match self.mkvs.get(ctx, &StatusKeyFmt(h).encode()) {
            Ok(Some(b)) => Ok(Some(self.decode_status(&b)?)),
            Ok(None) => Ok(None),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    /// Returns the list of all key manager statuses.
    pub fn statuses(&self, ctx: Context) -> Result<Vec<Status>, StateError> {
        let mut it = self.mkvs.iter(ctx);
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

    fn decode_status(&self, data: &[u8]) -> Result<Status, StateError> {
        cbor::from_slice(data).map_err(|err| StateError::Unavailable(anyhow!(err)))
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, default::Default, sync::Arc, vec};

    use io_context::Context;
    use rustc_hex::FromHex;

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
        consensus::keymanager::{EnclavePolicySGX, PolicySGX},
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

        // Setup protocol server with initialized mock consensus state.
        let server = ProtocolServer::new(Fixture::ConsensusMock.into());
        let mock_consensus_root = Root {
            version: 1,
            root_type: RootType::State,
            hash: Hash::from("f62f1f313de3833830a48b742f144fba542412e7ec65705d83f71a5e6e99bb2b"),
            ..Default::default()
        };
        let mkvs = Tree::builder()
            .with_capacity(100_000, 10_000_000)
            .with_root(mock_consensus_root)
            .build(server.read_sync());
        let keymanager_state = ImmutableState::new(&mkvs);

        let ctx = Arc::new(Context::background());

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
        let sig1 = Signature::from("37d04567456cab63004d54acacc60afb9d2315d5890401080d60b059cdd9088af5441974d0f53c2fca628877f0721780d8b79b66e92440ad120b44a5fce7be05");
        let sig2 = Signature::from("7d76c6d0914f32f3abd33db51d95ca13c03c9313f4eb84bbecc4c5571ff51373d65b774bafae3e82677a6d4dd35f30b1d6751db0b3acc5e1b2c7811b67bf9801");
        let checksum = "1bff211fae98c88ba82388ae954b88a71d3bbe327e162e9fa711fe7a1b759c3e"
            .from_hex()
            .unwrap();

        let expected_statuses = vec![
            Status {
                id: keymanager1,
                is_initialized: false,
                is_secure: false,
                checksum: vec![],
                nodes: vec![],
                policy: None,
            },
            Status {
                id: keymanager2,
                is_initialized: true,
                is_secure: true,
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
            },
        ];

        // Test statuses.
        let mut statuses = keymanager_state
            .statuses(Context::create_child(&ctx))
            .expect("statuses query should work");
        statuses.sort_by(|a, b| a.id.partial_cmp(&b.id).unwrap());
        assert_eq!(statuses, expected_statuses, "invalid statuses");

        // Test status.
        let status = keymanager_state
            .status(Context::create_child(&ctx), expected_statuses[1].id)
            .expect("status query should work")
            .expect("status query should return a result");
        assert_eq!(status, expected_statuses[1], "invalid status");

        let id =
            Namespace::from("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let status = keymanager_state
            .status(Context::create_child(&ctx), id)
            .expect("status query should work");
        assert_eq!(status, None, "invalid status");
    }
}
