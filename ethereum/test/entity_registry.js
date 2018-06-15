var registry = artifacts.require("./EntityRegistry.sol");

contract('EntityRegistry', function (accts) {
    it("should emit on registration", function () {
        var inst;

        var acct1 = accts[0];

        var closure = {
            resolve: function () { },
        };

        return registry.deployed().then(function (closure, instance) {
            inst = instance;
            var evt = inst.Entity({ fromBlock: 0, toBlock: 'latest' });
            evt.watch(function (err, resp) {
                if (closure.resolve != false) {
                    assert.equal(resp.args.id, "0xdeadbeef00000000deadbeef11111111deadbeef22222222deadbeef33333333", "Unexpected entity registration.");
                    closure.resolve();
                    closure.resolve = false;
                }
                evt.stopWatching();
            });
            return inst.register("0xdeadbeef00000000deadbeef11111111deadbeef22222222deadbeef33333333", { from: acct1 })
        }.bind(this, closure)).then(function (closure) {
            return new Promise(function (resolve, reject) {
                if (closure.resolve == false) {
                    resolve(true);
                } else {
                    closure.resolve = resolve;
                }
            });
        }.bind(this, closure))
    });

    it("supports deregistration", async function () {
        let acct1 = accts[0];

        let instance = await registry.deployed();

        var evt = instance.Entity({ fromBlock: 0, toBlock: 'latest' });

        var done = false;

        evt.watch(function (err, resp) {
            if (resp.logIndex == 0) {
                assert.equal(resp.args.id, "0xdeadbeef00000000deadbeef11111111deadbeef22222222deadbeef33333333", "Unexpected entity registration.");
                state = 1;
                var evt2 = instance.Dereg({ fromBlock: 0, toBlock: 'latest' });
                evt2.watch(function (err, resp) {
                    assert.equal(resp.args.id, "0x1234567812345678123456781234567812345678123456781234567812345678", "Unexpected entity registration.");
                    evt.stopWatching();
                    if (typeof done == 'function') {
                        done();
                    } else {
                        done = true;
                    }
                });
            }
        });


        await instance.register("0xdeadbeef00000000deadbeef11111111deadbeef22222222deadbeef33333333", { from: acct1 });

        await instance.deregister("0x1234567812345678123456781234567812345678123456781234567812345678", { from: acct1 });

        await new Promise(function (resolve) { if (done == false) { done = resolve; } else { resolve(); } })
    });
});