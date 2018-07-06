var RandomBeacon = artifacts.require("./RandomBeacon.sol");
var ContractDeployer = artifacts.require("./ContractDeployer.sol");
var MockEpoch = artifacts.require("./MockEpoch.sol");
var OasisEpoch = artifacts.require("./OasisEpoch.sol");
var ContractRegistry = artifacts.require("./ContractRegistry.sol")
var EntityRegistry = artifacts.require("./EntityRegistry.sol");
var UintSet = artifacts.require("./UintSet.sol");
var Stake = artifacts.require("./Stake.sol");
var DisputeResolution = artifacts.require("./DisputeResolution");

const deploy = async function (deployer, network) {
    if (network == "test") {
        // `truffle test` gives inconsistent/odd behavior when multiple
        // copies of the RandomBeacon contract are deployed at once.
        //
        // The tests only use the standard epoch timesource anyway.
        await deployer.deploy([OasisEpoch, MockEpoch]);
        await deployer.deploy(RandomBeacon, OasisEpoch.address);
        await deployer.deploy(UintSet);
        await deployer.link(UintSet, Stake);
        await deployer.deploy(Stake, 1, "EkidenStake", "E$");
        await deployer.deploy(ContractRegistry, OasisEpoch.address);
        await deployer.deploy(EntityRegistry, OasisEpoch.address, Stake.address);
        await deployer.deploy(DisputeResolution);
    } else {
        // truffle does not really support deploying more than 1 instance
        // of a given contract all that well yet, so this uses a nasty kludge
        // to deploy the RandomBeacon for each time source.
        await deployer.deploy([OasisEpoch, MockEpoch]);

        // Stake
        await deployer.deploy(UintSet);
        await deployer.link(UintSet, Stake);
        await deployer.deploy(Stake, 1000000000, "EkidenStake", "E$");

        let instance = await deployer.deploy(ContractDeployer, OasisEpoch.address, MockEpoch.address, Stake.address);
        let instance_addrs = await Promise.all([
            instance.oasis_beacon.call(),
            instance.mock_beacon.call(),
            instance.oasis_entity_registry.call(),
            instance.mock_entity_registry.call(),
            instance.oasis_contract_registry.call(),
            instance.mock_contract_registry.call()
        ]);
        await deployer.deploy(DisputeResolution);


        // Pass all the contract addresses to truffle_deploy in the rust
        // side as a simple JSON formatted dictionary.
        let addrs = {
            "RandomBeaconOasis": instance_addrs[0],
            "RandomBeaconMock": instance_addrs[1],
            "EntityRegistryOasis": instance_addrs[2],
            "EntityRegistryMock": instance_addrs[3],
            "ContractRegistryOasis": instance_addrs[4],
            "ContractRegistryMock": instance_addrs[5],
            "MockEpoch": MockEpoch.address,
            "Stake": Stake.address,
            "DisputeResolution": DisputeResolution.address
        };
        console.log("CONTRACT_ADDRESSES: " + JSON.stringify(addrs));
        Object.keys(addrs).forEach(function (key) {
            console.log("ENV_" + key + "=\"" + addrs[key].replace("0x", "") + "\"");
        });
    }
};

module.exports = function (deployer, network) {
    deployer.then(async function () { return await deploy(deployer, network); })
};
