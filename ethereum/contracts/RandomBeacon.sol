pragma solidity ^0.4.23;

import "./EpochABI.sol";

contract RandomBeacon {
    // The maximum time till an epoch transition, that the next epoch's beacon
    // can be pre-generated at.  This value should be long enough to ensure
    // that thre won't be down time on the epoch transition.
    uint64 constant pre_generate_slack = 600; // 10 minutes.

    // The EpochContract used for timekeeping;
    EpochContract epoch_source;

    // The stored random beacon value by epoch.
    struct Beacon {
        bytes32 entropy;
        bool initialized;
    }

    // The state variable that stores already generated beacons.
    mapping(uint64 => Beacon) public beacons;

    // The event emitted when the entropy for an epoch is generated.
    event OnGenerate(
        uint64 indexed _epoch,
        bytes32 _entropy
    );

    // Construct a new RandomBeacon contract instance, using the EpochContract
    // instance at `_epoch_addr`.
    constructor(address _epoch_addr) public {
        epoch_source = EpochContract(_epoch_addr);
    }

    function() public {
        revert();
    }

    // Generate and set the beacon if it does not exist.
    function set_beacon() public {
        (uint64 epoch, , uint64 till) = epoch_source.get_epoch(
            uint64(block.timestamp)
        );

        // Try to generate for the current epoch.
        bool did_generate = generate_beacon(epoch);

        // If it's sufficiently close to the epoch transition, pre-generate
        // the next epoch's beacon.
        if (till < pre_generate_slack) {
            did_generate = did_generate || generate_beacon(epoch+1);
        }

        require(did_generate);
    }

    // Get the random beacon entropy for the epoch corresponding to the
    // specified UNIX epoch time.
    function get_beacon(uint64 _timestamp) public view returns (uint64 epoch_, bytes32 entropy_) {
        (epoch_, ,) = epoch_source.get_epoch(_timestamp);

        Beacon storage b = beacons[epoch_];
        require(b.initialized);
        entropy_ = b.entropy;
    }

    // Generates pseudo-random (insecure) entropy.
    //
    // Note: The generation algorithm is similar to, but different from
    // the one used for dummy::InsecureDummyRandomBeacon.
    function generate_beacon(uint64 _epoch) internal returns (bool) {
        Beacon storage b = beacons[_epoch];
        if (!b.initialized) {
            // Generate the beacon value for the current epoch.
            b.entropy = keccak256(abi.encodePacked(
                "EkB-Ether",
                _epoch,
                blockhash(block.number-1)
            ));
            b.initialized = true;

            // Emit an event.
            emit OnGenerate(_epoch, b.entropy);

            return true;
        }
        return false;
    }
}
