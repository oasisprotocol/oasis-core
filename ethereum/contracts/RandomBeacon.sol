pragma solidity ^0.4.23;

import "./EpochABI.sol";

contract RandomBeacon {
    // The EpochContract used for timekeeping;
    EpochContract epoch_source;

    // The stored random beacon value by epoch.
    struct Beacon {
        bytes32 entropy;
        uint block_number;
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
        generate_beacon(epoch);
    }

    // Get the random beacon entropy for the epoch corresponding to the
    // specified UNIX epoch time.
    function get_beacon(uint64 _timestamp) public view
        returns (uint64 epoch_, bytes32 entropy_, uint block_number_) {
        (epoch_, ,) = epoch_source.get_epoch(_timestamp);

        Beacon storage b = beacons[epoch_];
        require(b.initialized);
        entropy_ = b.entropy;
        block_number_ = b.block_number;
    }

    // Generates pseudo-random (insecure) entropy, and emits the corresponding
    // event.  Iff the beacon already exists for the specified epoch, this
    // will `revert()`.
    //
    // Note: The generation algorithm is similar to, but different from
    // the one used for dummy::InsecureDummyRandomBeacon.
    function generate_beacon(uint64 _epoch) internal {
        Beacon storage b = beacons[_epoch];
        require(!b.initialized);

        // Generate the beacon value for the current epoch.
        b.entropy = keccak256(abi.encodePacked(
            "EkB-Ether",
            _epoch,
            blockhash(block.number-1)
        ));
        b.block_number = block.number;
        b.initialized = true;

        // Emit an event.
        emit OnGenerate(_epoch, b.entropy);
    }
}
