var RandomBeacon = artifacts.require("./RandomBeacon.sol");

module.exports = function (deployer) {
    deployer.deploy(RandomBeacon);
};
