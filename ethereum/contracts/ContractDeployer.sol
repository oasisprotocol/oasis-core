pragma solidity ^0.4.23;

import "./RandomBeacon.sol";
import "./EntityRegistry.sol";
import "./ContractRegistry.sol";

// Ugly workaround for https://github.com/trufflesuite/truffle/issues/237.
contract ContractDeployer {
    address public oasis_beacon;
    address public mock_beacon;
    address public oasis_entity_registry;
    address public mock_entity_registry;
    address public oasis_contract_registry;
    address public mock_contract_registry;

    constructor(address oasis_addr, address mock_addr) public {
        oasis_beacon = new RandomBeacon(oasis_addr);
        mock_beacon = new RandomBeacon(mock_addr);
        oasis_entity_registry = new EntityRegistry(oasis_addr);
        mock_entity_registry = new EntityRegistry(mock_addr);
        oasis_contract_registry = new ContractRegistry(oasis_addr);
        mock_contract_registry = new ContractRegistry(mock_addr);
    }
}
