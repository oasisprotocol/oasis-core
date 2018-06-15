pragma solidity ^0.4.23;

import "./EpochABI.sol";

contract EntityRegistry {
    event Entity(address indexed _from, bytes32 indexed id, uint64 epoch);
    event Dereg(address indexed _from, bytes32 indexed id, uint64 epoch);
    event Node(address indexed _from, bytes32 indexed id, uint64 epoch);

    EpochContract epoch_source;

    constructor(address epoch_addr) public {
        epoch_source = EpochContract(epoch_addr);
    }

    function() public {
        revert();
    }

    function register(bytes32 id) public {
        (uint64 epoch, , ) = epoch_source.get_epoch(uint64(block.timestamp));
        emit Entity(msg.sender, id, epoch);
    }

    function deregister(bytes32 id) public {
        (uint64 epoch, , ) = epoch_source.get_epoch(uint64(block.timestamp));
        emit Dereg(msg.sender, id, epoch);
    }

    function registerNode(bytes32 node) public {
        (uint64 epoch, , ) = epoch_source.get_epoch(uint64(block.timestamp));
        emit Node(msg.sender, node, epoch);
    }
}
