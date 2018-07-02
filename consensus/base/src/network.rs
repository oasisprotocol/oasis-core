//! Network interface required by consensus.
use std::convert::TryFrom;

use ekiden_common::bytes::B256;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_consensus_api as api;
use ekiden_scheduler_base::Role;

use super::{Block, Commitment, Reveal};

/// Consensus message content.
#[derive(Clone, Debug)]
pub enum Content {
    Commitment(Commitment),
    Reveal(Reveal),
    LatestBlock(Block),
}

impl TryFrom<api::Content> for Content {
    type Error = Error;

    fn try_from(other: api::Content) -> Result<Self> {
        match other.content {
            Some(api::Content_oneof_content::commitment(commitment)) => {
                Ok(Content::Commitment(Commitment::try_from(commitment)?))
            }
            Some(api::Content_oneof_content::reveal(reveal)) => {
                Ok(Content::Reveal(Reveal::try_from(reveal)?))
            }
            Some(api::Content_oneof_content::latest_block(block)) => {
                Ok(Content::LatestBlock(Block::try_from(block)?))
            }
            _ => Err(Error::new("unsupported message")),
        }
    }
}

impl Into<api::Content> for Content {
    fn into(self) -> api::Content {
        let mut other = api::Content::new();
        match self {
            Content::Commitment(commitment) => other.set_commitment(commitment.into()),
            Content::Reveal(reveal) => other.set_reveal(reveal.into()),
            Content::LatestBlock(block) => other.set_latest_block(block.into()),
        }

        other
    }
}

/// Consensus message.
///
/// Each message contains an authenticated sender's public key which is obtained
/// implicitly by the network layer (e.g., from gRPC authentication context for
/// simple topologies).
#[derive(Clone, Debug)]
pub struct Message {
    /// Authenticated sender.
    pub sender: B256,
    /// Message content.
    pub content: Content,
}

/// Message recipient.
#[derive(Clone, Debug)]
pub enum Recipient {
    /// A specific node.
    Node(B256),
    /// All nodes with a specific role.
    OnlyRole(Role),
    /// All nodes in the committee.
    AllNodes,
}

/// Network interface required by consensus.
pub trait ConsensusNetwork: Send + Sync {
    /// Subscribe to incoming messages from other nodes in the committee.
    fn watch_messages(&self) -> BoxStream<Message>;

    /// Send messages to other nodes in the committee.
    fn send(&self, recipient: Recipient, content: Content);
}
