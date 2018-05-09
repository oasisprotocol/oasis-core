pragma solidity ^0.4.23;

// Online IDE at https://remix.ethereum.org/#optimize=false&version=soljson-v0.4.23+commit.124ca40d.js

/**
 * @dev library for validating keccak256 commitments.
 */
library KECCAK {

    /**
     * @dev A commitment is a digest = keccak(value | nonce)
     */
    struct Commitment {
        bytes32 digest;
        bytes32 nonce;
    }

    /**
     * @dev Check if the digest was valid for a subsequently provided nonce.
     */
    function check(Commitment storage self, bytes32 data)
        public view
        returns (bool) {
        return keccak256((data | self.nonce)) == self.digest;
    }

    /**
     * @dev Check if the Commitment is 'instantiated' (is not the 0 instance)
     */
    function valid(Commitment storage self) public view returns (bool) {
        return self.digest != bytes32(0x0);
    }

    /**
     * @dev Check if the Commitment is in a "pre-commit" state.
     */
    function empty(Commitment storage self) public view returns (bool) {
        return self.digest == bytes32(0x1) || self.digest == bytes32(0x0);
    }

    /**
     * @dev Check if the Commitment is in a "commited, but not revealed" state.
     */
    function unrevealed(Commitment storage self) public view returns (bool) {
        return self.digest != bytes32(0x1) && self.nonce == bytes32(0x0);
    }

    /**
     * @dev Reset the commitment to the 'pre-commit' state.
     */
    function reset(Commitment storage self) internal {
        self.digest = 0x1;
        self.nonce = 0x0;
    }

    /**
     * @dev Reset the commitment to the 'zero' state.
     */
    function zero(Commitment storage self) internal {
        self.digest = 0x0;
    }
}

library Round {
    using KECCAK for KECCAK.Commitment;

    enum State { WaitingCommitment, WaitingRevealAndBlock }

    struct Data {
        address[] members;
        mapping (address => KECCAK.Commitment) commitments;
        uint32 outstanding_commitments;
        bytes32 current_block;
        bytes32 next_block;
        State state;
    }

    /**
     * @dev Verifies if reveals match commits match value
     */
    function verify_round(Data storage self) public view returns (bool) {
        for (uint member = 0; member < self.members.length; member++) {
            if (!self.commitments[self.members[member]].check(self.next_block)) {
                return false;
            }
        }
        return true;
    }

    function next_round(Data storage self) internal {
        for (uint member = 0; member < self.members.length; member++) {
            self.commitments[self.members[member]].reset();
        }
        self.current_block = self.next_block;
        self.next_block = bytes32(0x0);
    }

    function reset_round(Data storage self) internal {
        for (uint member = 0; member < self.members.length; member++) {
            self.commitments[self.members[member]].reset();
        }
        self.next_block = bytes32(0x0);
    }

    /**
     * @dev Throws if called by an account not on the onlyCommittee.
     */
    function onlyCommittee(Data storage self, address whom) public view returns (bool) {
        return self.commitments[whom].valid();
    }
}

contract Consensus {
    using Round for Round.Data;
    using KECCAK for KECCAK.Commitment;

    struct BlockHash {
        bytes32 hash;
    }

    /**
     * @dev Consensus events emitted by `new_event`.
     */
    enum ConsensusEvent { CommitmentsReceived, RoundFailed }

    /**
     * @dev The current round state.
     */
    Round.Data current_round;

    /**
     * @dev Emit events when new blocks are finalized.
     */
    event new_block(bytes32 hash);

    /**
     * @dev Emit synchronization events to committee members.
     */
    event new_event(ConsensusEvent ev);

    /**
     * @dev Make a commitment.
     */
    function commit (bytes32 digest) public {
        require(current_round.onlyCommittee(msg.sender));
        require(current_round.state == Round.State.WaitingCommitment);
        require(current_round.commitments[msg.sender].empty());
        require(digest != bytes32(0x0) && digest != bytes32(0x1));

        current_round.commitments[msg.sender].digest = digest;
        current_round.outstanding_commitments += 1;
        if (current_round.outstanding_commitments == current_round.members.length) {
            current_round.state = Round.State.WaitingRevealAndBlock;
            emit new_event(ConsensusEvent.CommitmentsReceived);
        }
    }

    /**
     * @dev Reveal a commitment.
     */
    function reveal (bytes32 nonce) public {
        require(current_round.onlyCommittee(msg.sender));
        require(current_round.state == Round.State.WaitingRevealAndBlock);
        require(current_round.commitments[msg.sender].unrevealed());
        require(nonce != bytes32(0x0) && nonce != bytes32(0x1));

        current_round.commitments[msg.sender].nonce = nonce;
        current_round.outstanding_commitments -= 1;

        if (current_round.outstanding_commitments == 0) {
            require(current_round.next_block != bytes32(0x0));
            if (current_round.verify_round()) {
                current_round.next_round();
                emit new_block(current_round.current_block);
            } else {
                current_round.reset_round();
                emit new_event(ConsensusEvent.RoundFailed);
            }
        }
    }

    /**
     * @dev Submit the block that commitments were made for.
     */
    function submit (bytes32 b) public {
        require(current_round.onlyCommittee(msg.sender));
        require(current_round.state == Round.State.WaitingRevealAndBlock);

        require(current_round.next_block == bytes32(0x0)); // Only submit if there is not already a pending block.
        current_round.next_block = b;
    }

    /**
     * @dev Update the members of the consensus based on the current block.
     */
    function update_membership(bytes[] b) public {
        require(current_round.state == Round.State.WaitingCommitment);
        require(keccak256(b) == current_round.current_block);
        // TODO: update current_round.members / commitments
        current_round.outstanding_commitments = 0;
    }

    /**
     * @dev Get the latest block hash.
     */
    function get_latest_block() public view returns (bytes32) {
        return current_round.current_block;
    }

    /**
     * @dev The Consensus constructor sets the original `committee` of the
     * contract.
     */
    constructor() internal { // Constructor
        // TODO: specify or hardcode initial committee.
    }

    function () internal { // Fallback function

    }
}
