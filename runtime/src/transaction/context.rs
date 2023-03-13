//! Runtime call context.
use std::sync::Arc;

use crate::{
    consensus::{
        beacon::EpochTime,
        roothash::{Header, RoundResults},
        state::ConsensusState,
        LightBlock,
    },
    protocol::Protocol,
    storage::MKVS,
};

/// Transaction context.
pub struct Context<'a> {
    /// Low-level access to the underlying Runtime Host Protocol.
    pub protocol: Arc<Protocol>,
    /// Consensus light block.
    pub consensus_block: &'a LightBlock,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: Arc<Protocol>,
        consensus_block: &'a LightBlock,
        consensus_state: ConsensusState,
        runtime_state: &'a mut dyn MKVS,
        header: &'a Header,
        epoch: EpochTime,
        round_results: &'a RoundResults,
        max_messages: u32,
        check_only: bool,
    ) -> Self {
        Self {
            protocol,
            consensus_block,
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
