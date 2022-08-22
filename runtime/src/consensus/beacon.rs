/// The number of intervals (epochs) since a fixed instant in time/block height (epoch date/height).
pub type EpochTime = u64;

/// An invalid epoch time.
pub const EPOCH_INVALID: EpochTime = 0xffffffffffffffff;

/// The epoch state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct EpochTimeState {
    pub epoch: EpochTime,
    pub height: i64,
}
