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
    pub fn round_roots(&self, id: Namespace, round: u64) -> Result<Option<RoundRoots>, Error> {
        match self
            .mkvs
            .get(&PastRootsKeyFmt((Hash::digest_bytes(id.as_ref()), round)).encode())
        {
            Ok(Some(b)) => {
                cbor::from_slice(&b).map_err(|err| StateError::Unavailable(anyhow!(err)).into())
            }
            Ok(None) => Ok(None),
            Err(err) => Err(StateError::Unavailable(anyhow!(err)).into()),
        }
    }

    // Returns all past round roots for the given runtime.
    pub fn past_round_roots(&self, id: Namespace) -> Result<BTreeMap<u64, RoundRoots>, Error> {
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
