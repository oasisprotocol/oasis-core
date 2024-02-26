//! Registry state in the consensus layer.
use anyhow::anyhow;

use crate::{
    common::{
        crypto::{
            hash::Hash,
            signature::{MultiSigned, PublicKey},
        },
        key_format::{KeyFormat, KeyFormatAtom},
        namespace::Namespace,
    },
    consensus::{
        registry::{Node, Runtime},
        state::StateError,
    },
    key_format,
    storage::mkvs::ImmutableMKVS,
};

/// Consensus registry state wrapper.
pub struct ImmutableState<'a, T: ImmutableMKVS> {
    mkvs: &'a T,
}

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Constructs a new ImmutableMKVS.
    pub fn new(mkvs: &'a T) -> ImmutableState<'a, T> {
        ImmutableState { mkvs }
    }
}

key_format!(SignedNodeKeyFmt, 0x11, Hash);
key_format!(RuntimeKeyFmt, 0x13, Hash);
key_format!(SuspendedRuntimeKeyFmt, 0x18, Hash);

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    fn decode_node(&self, data: &[u8]) -> Result<Node, StateError> {
        let signed: MultiSigned =
            cbor::from_slice(data).map_err(|err| StateError::Unavailable(anyhow!(err)))?;
        // The signed blob is transported as-is so we need to use non-strict decoding.
        cbor::from_slice_non_strict(&signed.blob)
            .map_err(|err| StateError::Unavailable(anyhow!(err)))
    }

    /// Looks up a specific node by its identifier.
    pub fn node(&self, id: &PublicKey) -> Result<Option<Node>, StateError> {
        let h = Hash::digest_bytes(id.as_ref());
        match self.mkvs.get(&SignedNodeKeyFmt(h).encode()) {
            Ok(Some(b)) => Ok(Some(self.decode_node(&b)?)),
            Ok(None) => Ok(None),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    /// Returns the list of all registered nodes.
    pub fn nodes(&self) -> Result<Vec<Node>, StateError> {
        let mut it = self.mkvs.iter();
        it.seek(&SignedNodeKeyFmt::default().encode_partial(0));

        let mut result: Vec<Node> = Vec::new();

        while let Some(value) = it
            .next()
            .and_then(|(key, value)| SignedNodeKeyFmt::decode(&key).map(|_| value))
        {
            result.push(self.decode_node(&value)?)
        }

        Ok(result)
    }

    fn decode_runtime(&self, data: &[u8]) -> Result<Runtime, StateError> {
        cbor::from_slice(data).map_err(|err| StateError::Unavailable(anyhow!(err)))
    }

    /// Looks up a specific runtime by its identifier.
    ///
    /// # Note
    ///
    /// This includes both non-suspended and suspended runtimes.
    pub fn runtime(&self, id: &Namespace) -> Result<Option<Runtime>, StateError> {
        let h = Hash::digest_bytes(id.as_ref());

        // Try non-suspended first.
        match self.mkvs.get(&RuntimeKeyFmt(h).encode()) {
            Ok(Some(b)) => Ok(Some(self.decode_runtime(&b)?)),
            Ok(None) => {
                // Also try suspended.
                match self.mkvs.get(&SuspendedRuntimeKeyFmt(h).encode()) {
                    Ok(Some(b)) => Ok(Some(self.decode_runtime(&b)?)),
                    Ok(None) => Ok(None),
                    Err(err) => Err(StateError::Unavailable(anyhow!(err))),
                }
            }
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        common::{
            crypto::{hash::Hash, signature},
            namespace::Namespace,
        },
        consensus::registry::{
            Capabilities, CapabilityTEE, ConsensusInfo, Node, NodeRuntime, P2PInfo, RuntimeKind,
            TEEHardware, TLSInfo, VRFInfo, VersionInfo,
        },
        storage::mkvs::{
            interop::{Fixture, ProtocolServer},
            Root, RootType, Tree,
        },
        Version,
    };

    use super::*;

    #[test]
    fn test_registry_state_interop() {
        // Keep in sync with go/consensus/cometbft/apps/registry/state/interop/interop.go.
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
        let registry_state = ImmutableState::new(&mkvs);

        // Test get nodes.
        let nodes = registry_state.nodes().expect("nodes query should work");
        assert_eq!(
            nodes.len(),
            2,
            "expected number of nodes should be returned"
        );

        let expected_nodes = vec![
                Node{
                    v: 3,
                    id: signature::PublicKey::from("43e5aaee54c768867718837ef4f6a6161e0615da0fcf8da394e5c8b7a0d54c18"),
                    entity_id: signature::PublicKey::from("761950dfe65936f6e9d06a0124bc930f7d5b1812ceefdfb2cae0ef5841291531"),
                    expiration: 32,
                    ..Default::default()
                },
                Node{
                    v: 3,
                    id: signature::PublicKey::from("f43c3559658f76b85d0630f56dc75d603807ac60be0ca3aada66799289066758"),
                    entity_id: signature::PublicKey::from("761950dfe65936f6e9d06a0124bc930f7d5b1812ceefdfb2cae0ef5841291531"),
                    expiration: 32,
                    tls: TLSInfo{
                        pub_key: signature::PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"),
                        ..Default::default()
                    },
                    p2p: P2PInfo{
                        id: signature::PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3"),
                        addresses: Some(Vec::new()),
                    },
                    consensus: ConsensusInfo{
                        id: signature::PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4"),
                        addresses: Some(Vec::new()),
                    },
                    vrf: VRFInfo{
                        id: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5"),
                    },
                    runtimes: Some(vec![
                        NodeRuntime{
                            id: Namespace::from("8000000000000000000000000000000000000000000000000000000000000010"),
                            version: Version::from(321),
                            ..Default::default()
                        },
                        NodeRuntime{
                            id: Namespace::from("8000000000000000000000000000000000000000000000000000000000000011"),
                            version: Version::from(123),
                            capabilities: Capabilities{
                               tee: Some(CapabilityTEE{
                                   hardware: TEEHardware::TEEHardwareIntelSGX,
                                    rak: signature::PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8"),
                                    attestation: vec![0, 1,2,3,4,5],
                                    ..Default::default()
                               }),
                            },
                            extra_info: Some(vec![5,3,2,1]),
                        },
                    ]),
                    ..Default::default()
                },
            ];
        assert_eq!(nodes, expected_nodes,);

        let node = registry_state
            .node(&expected_nodes.get(1).unwrap().id)
            .expect("node query should work");
        assert_eq!(node, Some(expected_nodes.get(1).unwrap().clone()));

        let node = registry_state
            .node(&signature::PublicKey::from(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ))
            .expect("node query should work");
        assert_eq!(node, None);

        let expected_runtimes = vec![
            Runtime {
                v: 3,
                id: Namespace::from(
                    "8000000000000000000000000000000000000000000000000000000000000010",
                ),
                entity_id: signature::PublicKey::from(
                    "761950dfe65936f6e9d06a0124bc930f7d5b1812ceefdfb2cae0ef5841291531",
                ),
                kind: RuntimeKind::KindCompute,
                tee_hardware: TEEHardware::TEEHardwareInvalid,
                deployments: vec![
                    VersionInfo {
                        version: Version::from(321),
                        valid_from: 42,
                        ..Default::default()
                    },
                    VersionInfo {
                        version: Version::from(320),
                        valid_from: 10,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
            Runtime {
                v: 3,
                id: Namespace::from(
                    "8000000000000000000000000000000000000000000000000000000000000011",
                ),
                entity_id: signature::PublicKey::from(
                    "761950dfe65936f6e9d06a0124bc930f7d5b1812ceefdfb2cae0ef5841291531",
                ),
                kind: RuntimeKind::KindCompute,
                tee_hardware: TEEHardware::TEEHardwareIntelSGX,
                deployments: vec![
                    VersionInfo {
                        version: Version::from(123),
                        valid_from: 42,
                        tee: vec![1, 2, 3, 4, 5],
                        bundle_checksum: vec![0x5; 32],
                    },
                    VersionInfo {
                        version: Version::from(120),
                        valid_from: 10,
                        tee: vec![5, 4, 3, 2, 1],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        ];

        for rt in expected_runtimes {
            let ext_rt = registry_state
                .runtime(&rt.id)
                .expect("runtime query should work");
            assert_eq!(ext_rt, Some(rt));
        }
    }
}
