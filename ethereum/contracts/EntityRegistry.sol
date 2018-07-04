pragma solidity ^0.4.23;

import "./EpochABI.sol";
import "./Stake.sol";

contract EntityRegistry {
    event Entity(address indexed _from, bytes32 indexed id, uint64 epoch);
    event Dereg(address indexed _from, bytes32 indexed id, uint64 epoch);
    event Node(address indexed _from, bytes32 indexed id, uint64 epoch);

    EpochContract epoch_source;
    Stake stake_source;

    address[] public nodes;
    // The reverse-map into nodes, to allow for efficient deletion.
    // Note: one-indexed, because 0-values are the same as unset.
    mapping(address => uint64) node_idxs;

    constructor(address epoch_addr, address stake_addr) public {
        epoch_source = EpochContract(epoch_addr);
        stake_source = Stake(stake_addr);
    }

    function() public {
        revert();
    }

    function register(bytes32 id) public {
        // TODO: validate stake.
        (uint64 epoch, , ) = epoch_source.get_epoch(uint64(block.timestamp));
        emit Entity(msg.sender, id, epoch);
    }

    function deregister(bytes32 id) public {
        (uint64 epoch, , ) = epoch_source.get_epoch(uint64(block.timestamp));

        // TODO: require deregistration in an epoch after registration.
        // TODO: require address has no stake in jeopardy at time of dereg.
        uint64 offset = node_idxs[msg.sender];
        if (offset != 0) {
            nodes[offset - 1] = nodes[nodes.length - 1];
            delete nodes[nodes.length - 1];
            nodes.length--;
            node_idxs[nodes[offset - 1]] = offset;
            node_idxs[msg.sender] = 0;
        }
        emit Dereg(msg.sender, id, epoch);
    }

    function registerNode(bytes32 node) public {
        // TODO: validate stake.
        (uint64 epoch, , ) = epoch_source.get_epoch(uint64(block.timestamp));

        require(node_idxs[msg.sender] == 0);
        require(nodes.length < 0xFFFFFFFFFFFFFFFF);
        node_idxs[msg.sender] = uint64(nodes.push(msg.sender));

        emit Node(msg.sender, node, epoch);
    }
}
