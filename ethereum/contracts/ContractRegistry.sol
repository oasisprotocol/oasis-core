pragma solidity ^0.4.23;

import "./EpochABI.sol";

contract ContractRegistry {
    //TODO: maybe should also index the bytes32 of the pubkey associated with the contract.
    event Contract(bytes32 indexed id, uint64 epoch);

    EpochContract epoch_source;

    constructor(address epoch_addr) public {
        epoch_source = EpochContract(epoch_addr);
    }

    function() public {
        revert();
    }

    function register(bytes32 id) public {
        (uint64 epoch, , ) = epoch_source.get_epoch(uint64(block.timestamp));
        emit Contract(id, epoch);
    }
}
