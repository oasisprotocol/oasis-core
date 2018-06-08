const MockEpoch = artifacts.require("MockEpoch");

const oasis_epoch_interval = 86400;

contract("MockEpoch test", async (accounts) => {
    it("should mimic epochtime::MockTimeSource", async () => {
        let instance = await MockEpoch.deployed();

        // The initial epoch should be 0 with till of 0.
        var [epoch, since, till] = await instance.get_epoch.call(0xdeadbeeffeedface);
        assert.equal(epoch, 0, "epoch != set");
        assert.equal(since, oasis_epoch_interval, "since != 1 day");
        assert.equal(till, 0, "till != 0");

        var contract_events = {};
        var events = instance.OnEpoch({}, {fromBlock: 0, toBlock: "latest"});
        events.watch(function(error, result) {
            assert.isNull(error, "Event error: " + error);

            // There should be one event, but the test enviromnent will produce
            // duplicates.  See: https://github.com/ethereum/web3.js/issues/398
            contract_events[result.transactionHash] = result;
        });

        const epoch_to_set = 23;
        const till_to_set = 17;

        // Set the epoch, and ensure get returns what was set.
        let set_res = await instance.set_epoch(epoch_to_set, till_to_set);
        [epoch, since, till] = await instance.get_epoch.call(0xdeadbeeffeedface);
        assert.equal(epoch, epoch_to_set, "epoch != set");
        assert.equal(since, oasis_epoch_interval - till_to_set, "since != (1 day - set)");
        assert.equal(till, till_to_set, "till != set");

        // Ensure the epoch/till value returned from get_epoch() corresponds
        // to the OnEpoch event emitted by set_epoch().
        let tx_hash = set_res.receipt.transactionHash;
        assert(contract_events.hasOwnProperty(tx_hash), "Didn't get event.");
        let args = contract_events[tx_hash].args;
        assert.equal(args._epoch.toString(), epoch.toString(), "Event epoch != Call epoch");
        assert.equal(args._till.toString(), till.toString(), "Event till != Call till");

        events.stopWatching();
    })
})
