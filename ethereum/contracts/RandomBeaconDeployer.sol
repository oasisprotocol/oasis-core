pragma solidity ^0.4.23;

import "./RandomBeacon.sol";

// Ugly workaround for https://github.com/trufflesuite/truffle/issues/237.
contract RandomBeaconDeployer {
    address public oasis_beacon;
    address public mock_beacon;

    constructor(address oasis_addr, address mock_addr) public {
        oasis_beacon = new RandomBeacon(oasis_addr);
        mock_beacon = new RandomBeacon(mock_addr);
    }
}
