var registry = artifacts.require("./ContractRegistry.sol");

contract('ContractRegistry', function (accts) {
    it("should emit on registration", function () {
        var inst;

        var acct1 = accts[0];
        var acct2 = accts[1];

        var closure = {
            resolve: function () { },
        };

        return registry.deployed().then(function (closure, instance) {
            inst = instance;
            var evt = inst.Contract({ fromBlock: 0, toBlock: 'latest' });
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
});