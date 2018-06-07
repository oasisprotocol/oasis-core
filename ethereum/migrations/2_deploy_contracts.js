var RandomBeacon = artifacts.require("./RandomBeacon.sol");
var MockEpoch = artifacts.require("./MockEpoch.sol");
var OasisEpoch = artifacts.require("./OasisEpoch.sol");

module.exports = function (deployer) {
    deployer.deploy(OasisEpoch).then(function() {
        return deployer.deploy(MockEpoch);
    }).then(function() {
        return deployer.deploy(RandomBeacon, OasisEpoch.address);
    });
};
