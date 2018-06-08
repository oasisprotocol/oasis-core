const OasisEpoch = artifacts.require("OasisEpoch");

const oasis_epoch_interval = 86400;

contract("Oasis Epoch test", async (accounts) => {
    it("should return epoch 0 at the Oasis Epoch", async () => {
        let instance = await OasisEpoch.deployed();

        const base = Date.parse("2018-01-01T00:00:00+00:00")/1000;
        let [epoch, since, till] = await instance.get_epoch.call(base);
        assert.equal(epoch, 0, "epoch != 0");
        assert.equal(since, 0, "since != 0");
        assert.equal(till, oasis_epoch_interval, "till != 1 day");
    })

    it("should transition when expected, and increment", async () => {
        let instance = await OasisEpoch.deployed();

        // One second prior to the transition.
        const one_before = Date.parse("2018-01-01T23:59:59+00:00")/1000;
        var [epoch, since, till] = await instance.get_epoch.call(one_before);
        assert.equal(epoch, 0, "epoch != 0");
        assert.equal(since, oasis_epoch_interval - 1, "since != (1 day - 1 sec)");
        assert.equal(till, 1, "till != 1 second");

        // The moment of the transition.
        const at_transition = Date.parse("2018-01-02T00:00:00+00:00")/1000;
        [epoch, since, till] = await instance.get_epoch.call(at_transition);
        assert.equal(epoch, 1, "epoch != 1");
        assert.equal(since, 0, "since != 0");
        assert.equal(till, oasis_epoch_interval, "till != 1 day");
    })

    it("should reject timestamps that pre-date the base", async () => {
        let instance = await OasisEpoch.deployed();

        const invalid = Date.parse("1997-08-29T02:14:00-04:00")/1000;
        try {
           let [epoch, since, till] = await instance.get_epoch.call(invalid);
        } catch (error) {
            return;
        }
        assert.fail("get_epoch() succeeded with a invalid timestamp");
    })
})
