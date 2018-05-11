//! Block type.
use ekiden_common::bytes::H256;
use ekiden_common::hash::EncodedHash;
use ekiden_common::uint::U256;
use ekiden_scheduler_base::CommitteeNode;

use super::commitment::Commitment;
use super::header::Header;
use super::transaction::Transaction;

/// Block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Block header.
    pub header: Header,
    /// Designated computation group.
    pub computation_group: Vec<CommitteeNode>,
    /// Ordered batch of transactions as defined by the group leader.
    pub transactions: Vec<Transaction>,
    /// Commitments from compute nodes in the same order as in the computation group.
    pub commitments: Vec<Commitment>,
}

impl Block {
    /// Generate a parent block from given child.
    pub fn new_parent_of(child: &Block) -> Block {
        let mut block = Block {
            header: Header {
                version: child.header.version,
                namespace: child.header.namespace,
                round: child.header.round + U256::from(1),
                previous_hash: child.header.get_encoded_hash(),
                group_hash: H256::zero(),
                transaction_hash: H256::zero(),
                state_root: H256::zero(),
                commitments_hash: H256::zero(),
            },
            computation_group: vec![],
            transactions: vec![],
            commitments: vec![],
        };

        block.update();
        block
    }

    /// Update header based on current block content.
    pub fn update(&mut self) {
        self.header.group_hash = self.computation_group.get_encoded_hash();
        self.header.transaction_hash = self.transactions.get_encoded_hash();
        self.header.commitments_hash = self.commitments.get_encoded_hash();
    }

    /// Check if block is internally consistent.
    ///
    /// This checks the following:
    ///   * Computation group matches the hash in the header.
    ///   * Transaction list matches the hash in the header.
    ///   * Commitments list matches the hash in the header.
    pub fn is_internally_consistent(&self) -> bool {
        self.computation_group.get_encoded_hash() == self.header.group_hash
            && self.transactions.get_encoded_hash() == self.header.transaction_hash
            && self.commitments.get_encoded_hash() == self.header.commitments_hash
    }
}

#[cfg(test)]
mod tests {
    use ekiden_common::bytes::B256;
    use ekiden_common::ring::signature::Ed25519KeyPair;
    use ekiden_common::signature::InMemorySigner;
    use ekiden_common::untrusted;

    use super::*;
    use super::super::*;

    #[test]
    fn test_block_commitment() {
        let block = Block::default();
        let nonce = B256::zero();
        let key_pair =
            Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
        let signer = InMemorySigner::new(key_pair);

        let header = block.header.clone();

        // Test commitment.
        let commitment = Commitment::new(&signer, &nonce, &header);
        assert!(commitment.verify());

        // Test reveal.
        let reveal = Reveal::new(&signer, &nonce, &header);
        assert!(reveal.verify());
        assert!(reveal.verify_commitment(&commitment));
        assert!(reveal.verify_value(&header));
    }
}
