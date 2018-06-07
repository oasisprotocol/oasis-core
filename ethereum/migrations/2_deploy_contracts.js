var RandomBeacon = artifacts.require("./RandomBeacon.sol");
var RandomBeaconDeployer = artifacts.require("./RandomBeaconDeployer.sol");
var MockEpoch = artifacts.require("./MockEpoch.sol");
var OasisEpoch = artifacts.require("./OasisEpoch.sol");

module.exports = function (deployer, network) {
    if (network == "test") {
        // `truffle test` gives inconsistent/odd behavior when multiple
        // copies of the RandomBeacon contract are deployed at once.
        //
        // The tests only use the standard epoch timesource anyway.
        deployer.deploy([ OasisEpoch, MockEpoch ]).then(function() {
            return deployer.deploy(RandomBeacon, OasisEpoch.address);
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
            // Placate truffle_deploy by spitting out the addresses of the
            // contracts created by the RandomBeaconDeployer in the format
            // it expects to see.
            console.log("  RandomBeaconOasis: " + beacon_addrs[0]);
            console.log("  RandomBeaconMock: " + beacon_addrs[1]);
        });
    }
};
