pragma solidity ^0.4.23;

import "./EpochABI.sol";

contract Consensus {
    // The EpochContract used for timekeeping.
    EpochContract epoch_source;

    // The placeholder invalid epoch.
    uint64 constant INVALID_EPOCH = 0xffffffffffffffff;
    // Signature size in bytes.
    uint constant SIGNATURE_SIZE = 65; // r, s, v (32, 32, 1 bytes)
    // Signature prefix (for web3.eth.sign compatibility).
    bytes constant SIGNATURE_PREFIX = "\x19Ethereum Signed Message:\n32";

    // The event emitted when workers or backups are eligible to submit
    // commitments.
    event OnWaitingCommitments(
        uint64 indexed _epoch,
        uint64 indexed _round,
        bool _is_discrepancy_resolution
    );

    // The event emitted when workers or backups are eligible to submit
    // reveals.
    event OnWaitingReveals(
        uint64 indexed _epoch,
        uint64 indexed _round,
        bool _is_discrepancy_resolution
    );

    // The event emitted when finalization happened.
    event OnFinalized(
        uint64 indexed _epoch,
        uint64 indexed _round,
        bytes32 _result
    );

    // The event emitted when the discrepancy resolution fails.
    event OnDiscrepancyFailed(
        uint64 indexed _epoch,
        uint64 indexed _round
    );

    // Consensus contract state.
    enum State {
        Invalid,
        WaitingCommitments,
        WaitingReveals,
        DiscrepancyWaitingCommitments,
        DiscrepancyWaitingReveals,
        DiscrepancyFailed
    }

    // A single node's commit and reveal.
    struct Commitment {
        bool exists;
        bytes32 commitment;
        bytes32 nonce;
    }

    // A consensus round.
    struct Round {
        uint64 epoch;
        uint64 count;
        address leader;
        address[] workers;
        address[] backups;
        mapping(address => Commitment) commitments;
    }

    // The contract owner.
    address public owner;

    // The current state.
    State public state;

    // The current round.
    Round public round;

    // Construct a new Consensus contract instance, using the EpochContract
    // isntance at `_epoch_addr`.
    constructor(address _epoch_addr) public {
        owner = msg.sender;
        epoch_source = EpochContract(_epoch_addr);
        round.epoch = INVALID_EPOCH;
    }

    function() public {
        revert();
    }

    modifier onlyLeaderOrOwner() {
        require(
            msg.sender == owner ||
            msg.sender == round.leader
        );
        _;
    }

    modifier onlyLeader() {
        require(msg.sender == round.leader);
        _;
    }

    // Register a fresh committee.
    function new_committee(
        uint64 _epoch,
        address _leader,
        address[] _workers,
        address[] _backups) external onlyLeaderOrOwner {

        // If the transaction sender is the contract owner, skip the state
        // checks as a way to manually recover from something going
        // horrifically wrong.
        if (msg.sender == round.leader) {
            require(
                state == State.Invalid ||
                state == State.WaitingCommitments ||
                state == State.DiscrepancyFailed
            );
        }

        // Check the supplied consensus epoch matches reality.
        (uint64 epoch, ,) = epoch_source.get_epoch(uint64(block.timestamp));
        require(_epoch == epoch);
        require(_workers.length > 0);

        // XXX: Figure out how to chain the previous committee to the current
        // beyond the modifier.

        // Purge the previous round state.
        _reset();
        round.workers.length = _workers.length;
        round.backups.length = _backups.length;

        // Build the new state.
        round.epoch = _epoch;
        round.leader = _leader;
        round.count = 0;
        for (uint i = 0; i < _workers.length; i++) {
            require(_workers[i] != _leader);
            round.workers[i] = _workers[i];
        }
        for (uint ii = 0; ii < _backups.length; ii++) {
            require(_backups[ii] != _leader);
            round.backups[ii] = _backups[ii];
        }
        // XXX: Enforce node uniqueness across all comittees.
        _prepare_workers();

        state = State.WaitingCommitments;
        emit OnWaitingCommitments(round.epoch, round.count, false);
    }


    // Post the aggregated commitments.
    function add_commitments(
        bytes32[] _signatures_r,
        bytes32[] _signatures_s,
        bytes _signatures_v,
        bytes32[] _commitments) external onlyLeader {

        require(
            state == State.WaitingCommitments ||
            state == State.DiscrepancyWaitingCommitments
        );
        require(
            _signatures_r.length == _signatures_s.length &&
            _signatures_s.length == _signatures_v.length
        );

        for (uint i = 0; i < _commitments.length; i++) {
            // Validate the signature, address, and that a commitment does
            // not exist already.
            (bool ok, address addr) = _verify_split_signature(
                _signatures_r[i],
                _signatures_s[i],
                uint8(_signatures_v[i]),
                _commitments[i]);

            Commitment storage c = round.commitments[addr];
            ok = ok && c.exists;
            ok = ok && (c.commitment == 0);
            if (!ok) {
                _on_consensus_failure();
                return;
            }

            // Store the address and commitment (nonce).
            c.commitment = _commitments[i];
        }
        if (_commitments.length != _expected_aggregates()) {
            // A commitment was missing.  Either the submitter is malicious,
            // or a node didn't post for aggregation.
            _on_consensus_failure();
            return;
        }

        bool is_discrepancy_resolution;
        if (state == State.WaitingCommitments) {
            state = State.WaitingReveals;
        } else {
            state = State.DiscrepancyWaitingReveals;
            is_discrepancy_resolution = true;
        }
        emit OnWaitingReveals(round.epoch, round.count, is_discrepancy_resolution);
    }

    // Post the aggregated reveals for this round.
    function add_reveals(
        bytes32[] _signatures_r,
        bytes32[] _signatures_s,
        bytes _signatures_v,
        bytes32[] _reveals) external onlyLeader {

        require(
            state == State.WaitingReveals ||
            state == State.DiscrepancyWaitingReveals
        );
        require(
            _signatures_r.length == _signatures_s.length &&
            _signatures_s.length == _signatures_v.length
        );

        bytes32 expected;
        for (uint i = 0; i < _reveals.length; i++) {
            // Validate the signature, address, and that a reveal does not
            // exist already.
            (bool ok, address addr) = _verify_split_signature(
                _signatures_r[i],
                _signatures_s[i],
                uint8(_signatures_v[i]),
                _reveals[i]);

            Commitment storage c = round.commitments[addr];
            ok = ok && c.exists;
            ok = ok && (c.nonce == 0);
            if (!ok) {
                _on_consensus_failure();
                return;
            }

            // Store the reveal (aka nonce).
            c.nonce = _reveals[i];

            // And attempt to validate it against the others.
            //
            // XXX: The slow path needs to vote, but doing that in solidity
            // will totally suck.
            if (i == 0) {
                // Use the first reveal for the expected value.
                expected = c.commitment ^ c.nonce;
            } else if (c.commitment ^ c.nonce != expected) {
                _on_consensus_failure();
                return;
            }
        }
        if (_reveals.length != _expected_aggregates()) {
            // A reveal was missing.  Either the submitter is malicious,
            // or a node didn't post for aggregation.
            _on_consensus_failure();
            return;
        }

        emit OnFinalized(round.epoch, round.count, expected);

        reset();
    }

    // Return a compact view of the contract state.
    function get_compact_state() external view returns (uint64 state_, uint64 epoch_, address leader_) {
        state_ = uint64(state);
        epoch_ = round.epoch;
        leader_ = round.leader;
    }

    // Reset the round state.
    function reset() internal onlyLeader {
        require(
            state != State.Invalid &&
            state != State.WaitingCommitments
        );

        _reset();
        _prepare_workers();
        round.count++;

        state = State.WaitingCommitments;
        emit OnWaitingCommitments(round.epoch, round.count, false);
    }

    // Verify a signature over a 32 byte message, and recover/return the
    // signer's address iff the signature is valid.
    function _verify_split_signature(
        bytes32 _r,
        bytes32 _s,
        uint8 _v,
        bytes32 _message
    ) internal pure returns (bool ok_, address addr_) {
        bytes32 sig_hash = keccak256(abi.encodePacked(
            SIGNATURE_PREFIX,
            _message));
        // web3.eth.sign and web3.accounts.sign disagree on how `v`
        // should be set.  See EIP-155.
        if (_v < 27) {
            _v += 27;
        }
        if (_v != 27 && _v != 28) {
            return (false, 0);
        }

        return (true, ecrecover(sig_hash, _v, _r, _s));
    }

    // Transition the state from the fast path to the slow path if possible.
    function _on_consensus_failure() internal {
        require(
            state != State.Invalid &&
            state != State.DiscrepancyFailed
        );

        // If the state already is in the slow path, then there is no recovery
        // possible.  Transition into a round failure state.
        if (
            state == State.DiscrepancyWaitingCommitments ||
            state == State.DiscrepancyWaitingReveals ||
            round.backups.length == 0
        ) {
            state = State.DiscrepancyFailed;
            emit OnDiscrepancyFailed(round.epoch, round.count);

            // Welp, move on to the next round.
            reset();
            return;
        }

        _reset_fast_path();
        _prepare_backups();

        state = State.DiscrepancyWaitingCommitments;
        emit OnWaitingCommitments(round.epoch, round.count, true);
    }

    // Prepare to use the workers.
    function _prepare_workers() internal {
        for (uint i = 0; i < round.workers.length; i++) {
            Commitment storage c = round.commitments[round.workers[i]];
            require(c.exists == false);
            require(c.commitment == 0);
            require(c.nonce == 0);
            c.exists = true;
        }
    }

    // Prepare to use the backups.
    function _prepare_backups() internal {
        for (uint i = 0; i < round.backups.length; i++) {
            Commitment storage c = round.commitments[round.backups[i]];
            require(c.exists == false);
            require(c.commitment == 0);
            require(c.nonce == 0);
            c.exists = true;
        }
    }

    // Reset the fast path state.
    function _reset_fast_path() internal {
        for (uint i = 0; i < round.workers.length; i++) {
            Commitment storage c = round.commitments[round.workers[i]];
            c.exists = false;
            c.commitment = bytes32(0);
            c.nonce = bytes32(0);
        }
    }

    // Reset the slow path state.
    function _reset_slow_path() internal {
        for (uint i = 0; i < round.backups.length; i++) {
            Commitment storage c = round.commitments[round.backups[i]];
            c.exists = false;
            c.commitment = bytes32(0);
            c.nonce = bytes32(0);
        }
    }

    // (Internal) Reset both states.
    function _reset() internal {
        _reset_fast_path();
        _reset_slow_path();
    }

    // Get the expected number of commits/reveals in the aggregated post.
    function _expected_aggregates() internal view returns (uint count_) {
        require(
            state != State.Invalid &&
            state != State.DiscrepancyFailed
        );

        if (
            state == State.WaitingCommitments ||
            state == State.WaitingReveals
        ) {
            count_ = round.workers.length;
        } else if (
            state == State.DiscrepancyWaitingCommitments ||
            state == State.DiscrepancyWaitingReveals
        ) {
            count_ = round.backups.length;
        } else {
            revert();
        }
    }
}
