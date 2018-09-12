//! Block type.
use std::convert::TryFrom;

use ekiden_common::bytes::H256;
use ekiden_common::error::Error;
use ekiden_common::hash::EncodedHash;
use ekiden_common::uint::U256;
use ekiden_scheduler_base::CommitteeNode;

use ekiden_roothash_api as api;

use super::commitment::Commitment;
use super::header::Header;

/// Block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Block header.
    pub header: Header,
    /// Designated computation group.
    pub computation_group: Vec<CommitteeNode>,
    /// Commitments from compute nodes in the same order as in the computation group.
    pub commitments: Vec<Option<Commitment>>,
}

impl Block {
    /// Generate a parent block from given child.
    pub fn new_parent_of(child: &Block) -> Block {
        let mut block = Block {
            header: Header {
                version: child.header.version,
                namespace: child.header.namespace,
                round: child.header.round + U256::from(1),
                timestamp: 0,
                previous_hash: child.header.get_encoded_hash(),
                group_hash: H256::zero(),
                input_hash: H256::zero(),
                output_hash: H256::zero(),
                state_root: H256::zero(),
                commitments_hash: H256::zero(),
            },
            computation_group: vec![],
            commitments: vec![],
        };

        block.update();
        block
    }

    /// Update header based on current block content.
    pub fn update(&mut self) {
        self.header.group_hash = self.computation_group.get_encoded_hash();
        self.header.commitments_hash = self.commitments.get_encoded_hash();
    }

    /// Check if block is internally consistent.
    ///
    /// This checks the following:
    ///   * Computation group matches the hash in the header.
    ///   * Commitments list matches the hash in the header.
    pub fn is_internally_consistent(&self) -> bool {
        self.computation_group.get_encoded_hash() == self.header.group_hash
            && self.commitments.get_encoded_hash() == self.header.commitments_hash
    }
}

impl TryFrom<api::Block> for Block {
    /// try_from Converts a protobuf block into a block.
    type Error = Error;
    fn try_from(a: api::Block) -> Result<Self, self::Error> {
        let header = Header::try_from(a.get_header().to_owned())?;
        let mut computation = Vec::new();
        for item in a.get_computation_group().iter() {
            computation.push(CommitteeNode::try_from(item.to_owned())?);
        }

        let mut commits = Vec::new();
        for item in a.get_commitments().iter() {
            if item.get_data().is_empty() {
                commits.push(None);
            } else {
                commits.push(Some(Commitment::try_from(item.to_owned())?));
            }
        }
        Ok(Block {
            header: header,
            computation_group: computation,
            commitments: commits,
        })
    }
}

impl Into<api::Block> for Block {
    /// Converts a block into a protobuf `api::Block` representation.
    fn into(self) -> api::Block {
        let mut b = api::Block::new();
        b.set_header(self.header.into());

        let mut groups = Vec::new();
        for item in self.computation_group {
            groups.push(item.into());
        }
        b.set_computation_group(groups.into());

        let mut commits = Vec::new();
        for item in self.commitments {
            match item {
                Some(item) => commits.push(item.into()),
                None => commits.push(api::Commitment::new()),
            }
        }
        b.set_commitments(commits.into());
        b
    }
}
