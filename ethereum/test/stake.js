const Stake = artifacts.require("Stake");

contract("Ethereum Stake test", async (accounts) => {
    it("should return correct name per test config", async () => {
	let instance = await Stake.deployed();
	let name = await instance.name.call();
	assert.equal(name, "EkidenStake");
	// matches configuration in ../migrations/2_deploy_contracts.js
    })

    it("should return correct symbol per test config", async () => {
	let instance = await Stake.deployed();
	let symbol = await instance.symbol.call();
	assert.equal(symbol, "E$");
	// matches configuration in ../migrations/2_deploy_contracts.js
    })

    it("should have decimals per contract", async () => {
	let instance = await Stake.deployed();
	let decimals = await instance.decimals.call();
	assert.equal(decimals, 18); // matches contract
    })

    it("should have correct initial balance via getBalance", async () => {
	let instance = await Stake.deployed();
	let decimals = await instance.decimals.call();
	let balance = await instance.balanceOf.call(accounts[0]);
	// balance is a BigNumber.
	assert.equal(balance.toNumber(), 1000000000 * 10**decimals);
	// matches configuration in ../migrations/2_deploy_contracts.js

	let ix = await instance.getIx.call(accounts[0]);
	console.log("accounts[0] index = " + ix);
	let len = await instance.getNumAccounts.call();
	console.log("num accts = " + len);
    })

    it("should allow transfers to 2nd account", async () => {
	let instance = await Stake.deployed();
	console.log("instance ok");

	var contract_events = {};
	var events = instance.Transfer({}, {fromBlock: 0, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    console.log(result);
	});

	console.log("accounts[0] = " + accounts[0]);
	console.log("accounts[1] = " + accounts[1]);

	var na; var a0_ix; var a1_ix;
	// na = await instance.getNumAccounts.call();
	// console.log("num accts = " + na);
	// a0_ix = await instance.getIx.call(accounts[0]);
	// console.log("accounts[0] ix = " + a0_ix);
	// a1_ix = await instance.getIx.call(accounts[1]);
	// console.log("accounts[1] ix = " + a1_ix);

	let transfer_status = await instance.transfer.call(
	    accounts[1], 1000, {from: accounts[0]});
	console.log("transfer done");
	console.log(transfer_status);
	assert(transfer_status);

	na = await instance.getNumAccounts.call();
	console.log("num accts = " + na);
	a0_ix = await instance.getIx.call(accounts[0]);
	console.log("accounts[0] = " + a0_ix);
	a1_ix = await instance.getIx.call(accounts[1]);
	console.log("accounts[1] = " + a1_ix);
	// assert(na == 2, "DOES NOT COMPUTE");

	// assert(Object.keys(contract_events).length > 0,
	//       "At least one Transfer event");

	// check balances
	let decimals = await instance.decimals.call();

	let a0_bal = await instance.balanceOf.call(accounts[0]);
	console.log(a0_bal);
	// assert.equal(a0_bal.toNumber(), (1000000000 * 10**decimals) - 1000);

	// let a1_bal = await instance.balanceOf.call(accounts[1]);
	// console.log(a1_bal);
	// assert.equal(a1_bal.toNumber(), 1000);
	events.stopWatching();
    })
})
