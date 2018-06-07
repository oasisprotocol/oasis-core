var RandomBeacon = artifacts.require("./RandomBeacon.sol");
var OasisEpoch = artifacts.require("./OasisEpoch.sol");

module.exports = function (deployer) {
    deployer.deploy(OasisEpoch).then(function() {
        return deployer.deploy(RandomBeacon, OasisEpoch.address);
    });
};
