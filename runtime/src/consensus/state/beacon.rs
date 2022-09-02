//! Beacon state in the consensus layer.
use anyhow::anyhow;
use io_context::Context;

use crate::{
    common::key_format::{KeyFormat, KeyFormatAtom},
    consensus::{
        beacon::{EpochTime, EpochTimeState},
        state::StateError,
    },
    key_format,
    storage::mkvs::ImmutableMKVS,
};

/// Consensus beacon state wrapper.
pub struct ImmutableState<'a, T: ImmutableMKVS> {
    mkvs: &'a T,
}

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Constructs a new ImmutableMKVS.
    pub fn new(mkvs: &'a T) -> ImmutableState<'a, T> {
        ImmutableState { mkvs }
    }
}

key_format!(CurrentEpochKeyFmt, 0x40, ());
key_format!(FutureEpochKeyFmt, 0x41, ());

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Returns the current epoch number.
    pub fn epoch(&self, ctx: Context) -> Result<EpochTime, StateError> {
        self.epoch_state(ctx).map(|es| es.epoch)
    }

    /// Returns the current epoch state.
    pub fn epoch_state(&self, ctx: Context) -> Result<EpochTimeState, StateError> {
        match self.mkvs.get(ctx, &CurrentEpochKeyFmt(()).encode()) {
            Ok(Some(b)) => {
                let state: EpochTimeState =
                    cbor::from_slice(&b).map_err(|err| StateError::Unavailable(anyhow!(err)))?;
                Ok(state)
            }
            Ok(None) => Ok(EpochTimeState::default()),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    /// Returns the future epoch number.
    pub fn future_epoch(&self, ctx: Context) -> Result<EpochTime, StateError> {
        self.future_epoch_state(ctx).map(|es| es.epoch)
    }

    /// Returns the future epoch state.
    pub fn future_epoch_state(&self, ctx: Context) -> Result<EpochTimeState, StateError> {
        match self.mkvs.get(ctx, &FutureEpochKeyFmt(()).encode()) {
            Ok(Some(b)) => {
                let state: EpochTimeState =
                    cbor::from_slice(&b).map_err(|err| StateError::Unavailable(anyhow!(err)))?;
                Ok(state)
            }
            Ok(None) => Ok(EpochTimeState::default()),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use crate::{
        common::crypto::hash::Hash,
        storage::mkvs::{
            interop::{Fixture, ProtocolServer},
            Root, RootType, Tree,
        },
    };

    use super::*;

    #[test]
    fn test_beacon_state_interop() {
        // Keep in sync with go/consensus/tendermint/apps/beacon/state/interop/interop.go.
        // If mock consensus state changes, update the root hash bellow.
        // See protocol server stdout for hash.

        // Setup protocol server with initialized mock consensus state.
        let server = ProtocolServer::new(Fixture::ConsensusMock.into());
        let mock_consensus_root = Root {
            version: 1,
            root_type: RootType::State,
            hash: Hash::from("9fd36f15cd4ff0b856de1606ddda9a08eeb14d73346b7b3a9e0f36e853b02a1e"),
            ..Default::default()
        };
        let mkvs = Tree::builder()
            .with_capacity(100_000, 10_000_000)
            .with_root(mock_consensus_root)
            .build(server.read_sync());
        let beacon_state = ImmutableState::new(&mkvs);

        let ctx = Arc::new(Context::background());

        // Test current epoch number.
        let epoch = beacon_state
            .epoch(Context::create_child(&ctx))
            .expect("epoch query should work");
        assert_eq!(42u64, epoch, "expected epoch should match");

        // Test current epoch state.
        let epoch_state = beacon_state
            .epoch_state(Context::create_child(&ctx))
            .expect("epoch state query should work");
        assert_eq!(42u64, epoch_state.epoch, "expected epoch should match");
        assert_eq!(13i64, epoch_state.height, "expected height should match");

        // Test future epoch number.
        let epoch = beacon_state
            .future_epoch(Context::create_child(&ctx))
            .expect("future epoch query should work");
        assert_eq!(43u64, epoch, "expected future epoch should match");

        // Test future epoch state.
        let epoch_state = beacon_state
            .future_epoch_state(Context::create_child(&ctx))
            .expect("future epoch state query should work");
        assert_eq!(43u64, epoch_state.epoch, "expected epoch should match");
        assert_eq!(15i64, epoch_state.height, "expected height should match");
    }
}
