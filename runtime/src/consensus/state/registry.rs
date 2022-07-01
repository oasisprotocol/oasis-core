//! Registry state in the consensus layer.
use anyhow::anyhow;
use io_context::Context;

use crate::{
    common::{
        crypto::{
            hash::Hash,
            signature::{MultiSigned, PublicKey},
        },
        key_format::{KeyFormat, KeyFormatAtom},
    },
    consensus::{registry::Node, state::StateError},
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

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    fn decode_node(&self, data: &[u8]) -> Result<Node, StateError> {
        let signed: MultiSigned =
            cbor::from_slice(data).map_err(|err| StateError::Unavailable(anyhow!(err)))?;
        // The signed blob is transported as-is so we need to use non-strict decoding.
        cbor::from_slice_non_strict(&signed.blob)
            .map_err(|err| StateError::Unavailable(anyhow!(err)))
    }

    /// Looks up a specific node by its identifier.
    pub fn node(&self, ctx: Context, id: &PublicKey) -> Result<Option<Node>, StateError> {
        let h = Hash::digest_bytes(id.as_ref());
        match self.mkvs.get(ctx, &SignedNodeKeyFmt(h).encode()) {
            Ok(Some(b)) => Ok(Some(self.decode_node(&b)?)),
            Ok(None) => Ok(None),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    /// Returns the list of all registered nodes.
    pub fn nodes(&self, ctx: Context) -> Result<Vec<Node>, StateError> {
        let mut it = self.mkvs.iter(ctx);
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
}

#[cfg(test)]
mod test {
    use std::{net::Ipv4Addr, sync::Arc};

    use crate::{
        common::{
            crypto::{hash::Hash, signature::PublicKey},
            namespace::Namespace,
        },
        consensus::registry::{
            Capabilities, CapabilityTEE, ConsensusInfo, Node, NodeRuntime, P2PInfo, TCPAddress,
            TEEHardware, TLSAddress, TLSInfo, VRFInfo,
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
        // Keep in sync with go/consensus/tendermint/apps/registry/state/interop/interop.go.
        // If mock consensus state changes, update the root hash bellow.
        // See protocol server stdout for hash.

        // Setup protocol server with initialized mock consensus state.
        let server = ProtocolServer::new(Fixture::ConsensusMock.into());
        let mock_consensus_root = Root {
            version: 1,
            root_type: RootType::State,
            hash: Hash::from("b84a7b8e22aae3a66484eea34b4bc9d74403e7af8aa41f701ba8d20a9c69c412"),
            ..Default::default()
        };
        let mkvs = Tree::builder()
            .with_capacity(100_000, 10_000_000)
            .with_root(mock_consensus_root)
            .build(server.read_sync());
        let registry_state = ImmutableState::new(&mkvs);

        let ctx = Arc::new(Context::background());

        // Test get nodes.
        let nodes = registry_state
            .nodes(Context::create_child(&ctx))
            .expect("nodes query should work");
        assert_eq!(
            nodes.len(),
            2,
            "expected number of nodes should be returned"
        );

        let expected_nodes = vec![
                Node{
                    v: 2,
                    id: PublicKey::from("43e5aaee54c768867718837ef4f6a6161e0615da0fcf8da394e5c8b7a0d54c18"),
                    entity_id: PublicKey::from("761950dfe65936f6e9d06a0124bc930f7d5b1812ceefdfb2cae0ef5841291531"),
                    expiration: 32,
                    ..Default::default()
                },
                Node{
                    v: 2,
                    id: PublicKey::from("f43c3559658f76b85d0630f56dc75d603807ac60be0ca3aada66799289066758"),
                    entity_id: PublicKey::from("761950dfe65936f6e9d06a0124bc930f7d5b1812ceefdfb2cae0ef5841291531"),
                    expiration: 32,
                    tls: TLSInfo{
                        pub_key: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"),
                        next_pub_key: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1"),
                        addresses: Some(vec![
                            TLSAddress{
                                pub_key: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2"),
                                address: TCPAddress{
                                    ip: Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped().octets().to_vec(),
                                    port: 1111,
                                    ..Default::default()
                                },
                            },
                        ]),
                    },
                    p2p: P2PInfo{
                        id: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3"),
                        addresses: Some(Vec::new()),
                    },
                    consensus: ConsensusInfo{
                        id: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4"),
                        addresses: Some(Vec::new()),
                    },
                    vrf: Some(VRFInfo{
                        id: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5"),
                    }),
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
                                    rak: PublicKey::from("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8"),
                                    attestation: vec![0, 1,2,3,4,5],
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
            .node(
                Context::create_child(&ctx),
                &expected_nodes.get(1).unwrap().id,
            )
            .expect("node query should work");
        assert_eq!(node, Some(expected_nodes.get(1).unwrap().clone()));

        let node = registry_state
            .node(
                Context::create_child(&ctx),
                &PublicKey::from(
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                ),
            )
            .expect("node query should work");
        assert_eq!(node, None);
    }
}
