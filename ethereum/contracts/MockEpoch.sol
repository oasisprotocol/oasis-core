pragma solidity ^0.4.23;

import "./EpochABI.sol";

contract MockEpoch is EpochContract {
    // The Oasis epoch interval.
    uint64 constant oasis_epoch_interval = 86400; // 1 day

    // The current epoch.
    uint64 current_epoch;
    // The current time till next epoch transition.
    uint64 current_till;

    // The contract owner.
    address owner;

    // The event emitted when a new epoch is set.
    event OnEpoch(
        uint64 indexed _epoch,
        uint64 _till
    );

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function() public {
        revert();
    }

    constructor() public {
        owner = msg.sender;
    }

    // Set the current mock epoch and time till epoch transition, emitting
    // a OnEpoch event iff the epoch has changed.
    function set_epoch(uint64 epoch, uint64 till) public onlyOwner {
        require(till <= oasis_epoch_interval);

        bool emit_event = epoch != current_epoch;
        current_epoch = epoch;
        current_till = till;

        if (emit_event) {
            emit OnEpoch(epoch, till);
        }
    }

    // Get the current mock epoch, and time since and till the next epoch
    // transition.  The provided timestamp value is ignored.
    function get_epoch(uint64 /* timestamp */) public view returns (uint64 epoch, uint64 since, uint64 till) {
        epoch = current_epoch;
        till = current_till;
        since = oasis_epoch_interval - till;
    }
}
