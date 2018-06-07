pragma solidity ^0.4.23;

contract OasisEpoch {
    // The Oasis epoch relative to the Unix epoch.
    uint64 constant oasis_epoch = 1514764800; // 2018-01-01T00:00:00+00:00
    // The Oasis epoch interval.
    uint64 constant oasis_epoch_interval = 86400; // 1 day
    // The placeholder invalid Oasis epoch.
    uint64 constant oasis_epoch_invalid = 0xffffffffffffffff;

    function() public {
        revert();
    }

    // Get the current Oasis epoch, and time since and till the next epoch
    // transition from a timestamp expressed as the number of seconds since
    // the UNIX epoch.
    function get_epoch(uint64 timestamp) public pure returns (uint64 epoch, uint64 since, uint64 till) {
        require(timestamp >= oasis_epoch);

        timestamp = timestamp - oasis_epoch; // Start at the Oasis epoch.
        epoch = timestamp / oasis_epoch_interval;
        since = timestamp % oasis_epoch_interval;
        till = oasis_epoch_interval - since;
        assert(epoch != oasis_epoch_invalid);
    }
}
