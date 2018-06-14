const RandomBeacon = artifacts.require("RandomBeacon");

function unix_time() {
    return Math.floor(new Date()/1000);
}

contract("Ethereum RandomBeacon test", async (accounts) => {
    it("should fail horribly till someone calls set_beacon()", async () => {
        let instance = await RandomBeacon.deployed();
        try {
          let res = await instance.get_beacon.call(unix_time());
        } catch (error) {
          return;
        }
        assert.fail("get_beacon() suceeded without a beacon");
    })

    it("should return something if someone calls set_beacon() first", async () => {
        let instance = await RandomBeacon.deployed();

        var contract_events = {};
        var events = instance.OnGenerate({},{fromBlock: 0, toBlock: "latest"});
        events.watch(function(error, result){
            assert.isNull(error, "Event error: " + error);

            // Suppress duplicate events.
            // See: https://github.com/ethereum/web3.js/issues/398
            contract_events[result.transactionHash] = result;
        });

        let set_res = await instance.set_beacon();
        let res = await instance.get_beacon.call(unix_time());

        // Ensure that at least one OnGenerate event was received.
        assert(Object.keys(contract_events).length > 0, "Not at least 1 OnGenerate");

        // Ensure the epoch/entropy/block_number value returned from
        // get_beacon() corresponds to a OnGenerate event emitted by the
        // set_beacon().
        var got_OnGenerate = false;
        for (var tx_hash in contract_events) {
            if (!contract_events.hasOwnProperty(tx_hash)) {
                continue;
            }
            let ev = contract_events[tx_hash];

            let args = ev.args;
            if (args._epoch.toString() == res[0].toString()) {
                assert.equal(args._entropy, res[1], "Event entropy != Call entropy");
                got_OnGenerate = true;
            }
            assert.equal(res[2], ev.blockNumber, "Event blockNumber != Call block_number");
        }
        assert(got_OnGenerate, "Didn't find OnGenerate event with the get_beacon() results");

        events.stopWatching();
    })
})
