//! Root hash backend interface.
use ekiden_common::{bytes::B256, futures::BoxStream, uint::U256};

use super::Block;

/// Root hash backend interface.
pub trait RootHashBackend: Sync + Send {
    /// Return a stream of blocks.
    ///
    /// The latest block will get pushed into the stream. Then, subsequent blocks will get pushed
    /// into the stream as they are confirmed by the root hash backend.
    fn get_blocks(&self, runtime_id: B256) -> BoxStream<Block>;

    /// Return a stream of blocks starting with the one from a specified round.
    ///
    /// The one at the specified round is included. Later blocks are pushed in order, and blocks
    /// will get pushed as they are confirmed.
    fn get_blocks_since(&self, runtime_id: B256, round: U256) -> BoxStream<Block>;
}
