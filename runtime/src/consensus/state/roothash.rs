//! Roothash state in the consensus layer.
use std::convert::TryInto;

use anyhow::anyhow;
use io_context::Context;

use crate::{
    common::{
        crypto::hash::Hash,
        key_format::{KeyFormat, KeyFormatAtom},
        namespace::Namespace,
    },
    consensus::{roothash::Error, state::StateError},
    key_format,
    storage::mkvs::ImmutableMKVS,
};

/// Consensus staking state wrapper.
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

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Returns the state root for a specific runtime.
    pub fn state_root(&self, ctx: Context, id: Namespace) -> Result<Hash, Error> {
        match self.mkvs.get(
            ctx,
            &StateRootKeyFmt(Hash::digest_bytes(id.as_ref())).encode(),
        ) {
            Ok(Some(b)) => Ok(Hash(b.try_into().map_err(|_| -> Error {
                StateError::Unavailable(anyhow!("corrupted hash value")).into()
            })?)),
            Ok(None) => Err(Error::InvalidRuntime(id)),
            Err(err) => Err(StateError::Unavailable(anyhow!(err)).into()),
        }
    }
}
