//! Roothash state in the consensus layer.
use std::{collections::BTreeMap, convert::TryInto};

use anyhow::anyhow;

use crate::{
    common::{
        crypto::hash::Hash,
        key_format::{KeyFormat, KeyFormatAtom},
        namespace::Namespace,
    },
    consensus::{
        roothash::{Error, RoundResults, RoundRoots},
        state::StateError,
    },
    key_format,
    storage::mkvs::ImmutableMKVS,
};

/// Consensus roothash state wrapper.
pub struct ImmutableState<'a, T: ImmutableMKVS> {
    mkvs: &'a T,
}

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Constructs a new ImmutableMKVS.
    pub fn new(mkvs: &'a T) -> ImmutableState<'a, T> {
        ImmutableState { mkvs }
    }
}

key_format!(StateRootKeyFmt, 0x25, Hash);
key_format!(LastRoundResultsKeyFmt, 0x27, Hash);
key_format!(PastRootsKeyFmt, 0x2a, (Hash, u64));

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Returns the state root for a specific runtime.
    pub fn state_root(&self, id: Namespace) -> Result<Hash, Error> {
        match self
            .mkvs
            .get(&StateRootKeyFmt(Hash::digest_bytes(id.as_ref())).encode())
        {
            Ok(Some(b)) => Ok(Hash(b.try_into().map_err(|_| -> Error {
                StateError::Unavailable(anyhow!("corrupted hash value")).into()
            })?)),
            Ok(None) => Err(Error::InvalidRuntime(id)),
            Err(err) => Err(StateError::Unavailable(anyhow!(err)).into()),
        }
    }

    /// Returns the last round results for a specific runtime.
    pub fn last_round_results(&self, id: Namespace) -> Result<RoundResults, Error> {
        match self
            .mkvs
            .get(&LastRoundResultsKeyFmt(Hash::digest_bytes(id.as_ref())).encode())
        {
            Ok(Some(b)) => {
                cbor::from_slice(&b).map_err(|err| StateError::Unavailable(anyhow!(err)).into())
            }
            Ok(None) => Err(Error::InvalidRuntime(id)),
            Err(err) => Err(StateError::Unavailable(anyhow!(err)).into()),
        }
    }

    // Returns the state and I/O roots for the given runtime and round.
    pub fn round_roots(&self, id: Namespace, round: u64) -> Result<Option<RoundRoots>, StateError> {
        match self
            .mkvs
            .get(&PastRootsKeyFmt((Hash::digest_bytes(id.as_ref()), round)).encode())
        {
            Ok(Some(b)) => {
                cbor::from_slice(&b).map_err(|err| StateError::Unavailable(anyhow!(err)))
            }
            Ok(None) => Ok(None),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    // Returns all past round roots for the given runtime.
    pub fn past_round_roots(&self, id: Namespace) -> Result<BTreeMap<u64, RoundRoots>, StateError> {
        let h = Hash::digest_bytes(id.as_ref());
        let mut it = self.mkvs.iter();
        it.seek(&PastRootsKeyFmt((h, Default::default())).encode_partial(1));

        let mut result: BTreeMap<u64, RoundRoots> = BTreeMap::new();

        for (round, value) in it.map_while(|(key, value)| {
            PastRootsKeyFmt::decode(&key)
                .filter(|PastRootsKeyFmt((ns, _))| ns == &h)
                .map(|PastRootsKeyFmt((_, round))| (round, value))
        }) {
            result.insert(
                round,
                cbor::from_slice(&value).map_err(|err| StateError::Unavailable(anyhow!(err)))?,
            );
        }

        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use crate::storage::mkvs::{
        interop::{Fixture, ProtocolServer},
        Root, RootType, Tree,
    };

    use super::*;
    #[test]
    fn test_roothash_state_interop() {
        // Keep in sync with go/consensus/cometbft/apps/roothash/state/interop/interop.go.
        // If mock consensus state changes, update the root hash bellow.
        // See protocol server stdout for hash.
        // To make the hash show up during tests, run "cargo test" as
        // "cargo test -- --nocapture".

        // Setup protocol server with initialized mock consensus state.
        let server = ProtocolServer::new(Fixture::ConsensusMock.into());
        let mock_consensus_root = Root {
            version: 1,
            root_type: RootType::State,
            hash: Hash::from("3c4cfd92b0aea7da65e6d083c69e4424aa87376735a8f0a5ada7fd0547343f66"),
            ..Default::default()
        };
        let mkvs = Tree::builder()
            .with_capacity(100_000, 10_000_000)
            .with_root(mock_consensus_root)
            .build(server.read_sync());
        let state = ImmutableState::new(&mkvs);

        let runtime_id =
            Namespace::from("8000000000000000000000000000000000000000000000000000000000000010");

        // Test fetching past round roots.
        let past_round_roots = state
            .past_round_roots(runtime_id)
            .expect("past round roots query should work");
        assert_eq!(
            10,
            past_round_roots.len(),
            "expected number of roots should match"
        );
        past_round_roots.iter().for_each(|(round, roots)| {
            assert_eq!(
                RoundRoots {
                    state_root: Hash::digest_bytes(format!("state {}", round).as_bytes()),
                    io_root: Hash::digest_bytes(format!("io {}", round).as_bytes())
                },
                *roots,
                "expected roots should match"
            );
        });

        // Test fetching latest round roots.
        let round_roots = state
            .round_roots(runtime_id, 100)
            .expect("round roots query should work");
        assert_eq!(None, round_roots, "round root should be missing");

        let round_roots = state
            .round_roots(runtime_id, 10)
            .expect("round roots query should work");
        assert_eq!(
            Some(RoundRoots {
                state_root: Hash::digest_bytes(format!("state {}", 10).as_bytes()),
                io_root: Hash::digest_bytes(format!("io {}", 10).as_bytes())
            }),
            round_roots,
            "round root should be missing"
        );

        // Test non-existing runtime.
        let runtime_id =
            Namespace::from("8000000000000000000000000000000000000000000000000000000000000000");
        let past_round_roots = state
            .past_round_roots(runtime_id)
            .expect("past round roots query should work");
        assert_eq!(
            0,
            past_round_roots.len(),
            "there should be no roots for non-existing runtime"
        );
        let round_roots = state
            .round_roots(runtime_id, 10)
            .expect("round roots query should work");
        assert_eq!(
            None, round_roots,
            "round root should be missing for non-existing runtime"
        )
    }
}
