//! Beacon state in the consensus layer.
use anyhow::anyhow;

use crate::{
    common::key_format::{KeyFormat, KeyFormatAtom},
    consensus::{
        beacon::{EpochTime, EpochTimeState},
        state::StateError,
    },
    key_format,
    storage::mkvs::{FallibleMKVS, ImmutableMKVS},
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
    pub fn epoch(&self) -> Result<EpochTime, StateError> {
        self.epoch_state().map(|es| es.epoch)
    }

    /// Returns the current epoch state.
    pub fn epoch_state(&self) -> Result<EpochTimeState, StateError> {
        match self.mkvs.get(&CurrentEpochKeyFmt(()).encode()) {
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
    pub fn future_epoch(&self) -> Result<EpochTime, StateError> {
        self.future_epoch_state().map(|es| es.epoch)
    }

    /// Returns the future epoch state.
    pub fn future_epoch_state(&self) -> Result<EpochTimeState, StateError> {
        match self.mkvs.get(&FutureEpochKeyFmt(()).encode()) {
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

/// Mutable consensus beacon state wrapper.
pub struct MutableState;

impl MutableState {
    /// Set current epoch state.
    pub fn set_epoch_state<S: FallibleMKVS>(
        mkvs: &mut S,
        epoch_state: EpochTimeState,
    ) -> Result<(), StateError> {
        mkvs.insert(&CurrentEpochKeyFmt(()).encode(), &cbor::to_vec(epoch_state))?;
        Ok(())
    }

    /// Set future epoch state.
    pub fn set_future_epoch_state<S: FallibleMKVS>(
        mkvs: &mut S,
        epoch_state: EpochTimeState,
    ) -> Result<(), StateError> {
        mkvs.insert(&FutureEpochKeyFmt(()).encode(), &cbor::to_vec(epoch_state))?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        common::crypto::hash::Hash,
        storage::mkvs::{
            interop::{Fixture, ProtocolServer},
            sync::NoopReadSyncer,
            Root, RootType, Tree,
        },
    };

    use super::*;

    #[test]
    fn test_mutable_state() {
        let mut mkvs = Tree::builder()
            .with_root_type(RootType::State)
            .build(Box::new(NoopReadSyncer));

        MutableState::set_epoch_state(
            &mut mkvs,
            EpochTimeState {
                epoch: 10,
                height: 100,
            },
        )
        .unwrap();

        MutableState::set_future_epoch_state(
            &mut mkvs,
            EpochTimeState {
                epoch: 11,
                height: 110,
            },
        )
        .unwrap();

        let beacon_state = ImmutableState::new(&mkvs);

        // Test current epoch state.
        let epoch_state = beacon_state
            .epoch_state()
            .expect("epoch state query should work");
        assert_eq!(10u64, epoch_state.epoch, "expected epoch should match");
        assert_eq!(100i64, epoch_state.height, "expected height should match");

        // Test future epoch state.
        let epoch_state = beacon_state
            .future_epoch_state()
            .expect("future epoch state query should work");
        assert_eq!(11u64, epoch_state.epoch, "expected epoch should match");
        assert_eq!(110i64, epoch_state.height, "expected height should match");
    }

    #[test]
    fn test_beacon_state_interop() {
        // Keep in sync with go/consensus/cometbft/apps/beacon/state/interop/interop.go.
        // If mock consensus state changes, update the root hash bellow.
        // See protocol server stdout for hash.
        // To make the hash show up during tests, run "cargo test" as
        // "cargo test -- --nocapture".

        // Setup protocol server with initialized mock consensus state.
        let server = ProtocolServer::new(Fixture::ConsensusMock.into());
        let mock_consensus_root = Root {
            version: 1,
            root_type: RootType::State,
            hash: Hash::from("123d46d530ebb004f6de9da7e1f41f7acde10b824e79ca8e718651dab2047c23"),
            ..Default::default()
        };
        let mkvs = Tree::builder()
            .with_capacity(100_000, 10_000_000)
            .with_root(mock_consensus_root)
            .build(server.read_sync());
        let beacon_state = ImmutableState::new(&mkvs);

        // Test current epoch number.
        let epoch = beacon_state.epoch().expect("epoch query should work");
        assert_eq!(42u64, epoch, "expected epoch should match");

        // Test current epoch state.
        let epoch_state = beacon_state
            .epoch_state()
            .expect("epoch state query should work");
        assert_eq!(42u64, epoch_state.epoch, "expected epoch should match");
        assert_eq!(13i64, epoch_state.height, "expected height should match");

        // Test future epoch number.
        let epoch = beacon_state
            .future_epoch()
            .expect("future epoch query should work");
        assert_eq!(43u64, epoch, "expected future epoch should match");

        // Test future epoch state.
        let epoch_state = beacon_state
            .future_epoch_state()
            .expect("future epoch state query should work");
        assert_eq!(43u64, epoch_state.epoch, "expected epoch should match");
        assert_eq!(15i64, epoch_state.height, "expected height should match");
    }
}
