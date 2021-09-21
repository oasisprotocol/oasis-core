//! Runtime call context.
use std::sync::Arc;

use io_context::Context as IoContext;

use crate::{
    consensus::{
        beacon::EpochTime,
        roothash::{Header, RoundResults},
        state::ConsensusState,
    },
    storage::MKVS,
};

/// Transaction context.
pub struct Context<'a> {
    /// I/O context.
    pub io_ctx: Arc<IoContext>,
    /// Consensus state tree.
    pub consensus_state: ConsensusState,
    /// Runtime state.
    pub runtime_state: &'a mut dyn MKVS,
    /// The block header accompanying this transaction.
    pub header: &'a Header,
    /// Epoch corresponding to the currently processed block.
    pub epoch: EpochTime,
    /// Results of processing the previous successful round.
    pub round_results: &'a RoundResults,
    /// The maximum number of messages that can be emitted in this round.
    pub max_messages: u32,
    /// Flag indicating whether to only perform transaction check rather than
    /// running the transaction.
    pub check_only: bool,
}

impl<'a> Context<'a> {
    /// Construct new transaction context.
    pub fn new(
        io_ctx: Arc<IoContext>,
        consensus_state: ConsensusState,
        runtime_state: &'a mut dyn MKVS,
        header: &'a Header,
        epoch: EpochTime,
        round_results: &'a RoundResults,
        max_messages: u32,
        check_only: bool,
    ) -> Self {
        Self {
            io_ctx,
            consensus_state,
            runtime_state,
            header,
            epoch,
            round_results,
            max_messages,
            check_only,
        }
    }
}
