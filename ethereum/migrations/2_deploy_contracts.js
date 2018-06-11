var RandomBeacon = artifacts.require("./RandomBeacon.sol");
var RandomBeaconDeployer = artifacts.require("./RandomBeaconDeployer.sol");
var MockEpoch = artifacts.require("./MockEpoch.sol");
var OasisEpoch = artifacts.require("./OasisEpoch.sol");
var Stake = artifacts.require("./Stake.sol");

module.exports = function (deployer, network) {
    if (network == "test") {
        // `truffle test` gives inconsistent/odd behavior when multiple
        // copies of the RandomBeacon contract are deployed at once.
        //
        // The tests only use the standard epoch timesource anyway.
        deployer.deploy([ OasisEpoch, MockEpoch ]).then(function() {
            return deployer.deploy(RandomBeacon, OasisEpoch.address);
        }).then(function() {
	    return deployer.deploy(Stake, 1000000000, "EkidenStake", "E$");
	});
    } else {
        // truffle does not really support deploying more than 1 instance
        // of a given contract all that well yet, so this uses a nasty kludge
        // to deploy the RandomBeacon for each time source.
        deployer.deploy([ OasisEpoch, MockEpoch ]).then(function() {
            return deployer.deploy(
                RandomBeaconDeployer,
                OasisEpoch.address,
                MockEpoch.address
            );
        }).then(function(instance) {
            return Promise.all([
                instance.oasis_beacon.call(),
                instance.mock_beacon.call()
            ]);
        }).then(function(beacon_addrs) {
            // Pass all the contract addresses to truffle_deploy in the rust
            // side as a simple JSON formatted dictionary.
            let addrs = {
                "RandomBeaconOasis": beacon_addrs[0],
                "RandomBeaconMock": beacon_addrs[1],
                "MockEpoch": MockEpoch.address
            };
            console.log("CONTRACT_ADDRESSES: " + JSON.stringify(addrs));
        }).then(function() {
	    return deployer.deploy(1000000000, "Ekiden Stake", "E$");
	});
    }
};
