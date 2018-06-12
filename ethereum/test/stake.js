const Stake = artifacts.require("Stake");

contract("Ethereum Stake test", async (accounts) => {
    let initial_allocation = 1;
    let transfer_amount = 1000;
    let BN_initial_allocation = web3.toBigNumber(initial_allocation);
    let BN_transfer_amount = web3.toBigNumber(transfer_amount);
    let BN_10 = web3.toBigNumber(10);
    let small_allowance = 4321;
    let BN_small_allowance = web3.toBigNumber(small_allowance);
    let BN_large_allowance = web3.toBigNumber(10).pow(web3.toBigNumber(20));
    var block_num = 0;
    // large_allowance is greater than available balance, which is allowed

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
	var initial = BN_initial_allocation
	    .times(BN_10.pow(web3.toBigNumber(decimals)));
	// assert.equal(balance.toNumber(), initial_allocation * 10**decimals);
	assert(balance.eq(initial), "Initial balance wrong");
	// matches configuration in ../migrations/2_deploy_contracts.js
    })

    it("should allow transfers to 2nd account", async () => {
	let instance = await Stake.deployed();

	var contract_events = {};
	var events;
	var reverted;

	events = instance.Transfer({}, {fromBlock: block_num, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;  // see transfers below
	});

	let transfer_status = await instance.transfer(
	    accounts[1], transfer_amount, {from: accounts[0]});
	events.stopWatching();
	assert(transfer_status, "transfer to 2nd account should succeed");

	// check balances
	let decimals = await instance.decimals.call();

	var a0_bal = await instance.balanceOf.call(accounts[0]);
	var expected = BN_initial_allocation
	    .times(BN_10.pow(web3.toBigNumber(decimals)))
	    .minus(BN_transfer_amount);
	assert(expected.eq(a0_bal),
	       "post-transfer balance for 1st account incorrect");

	let a1_bal = await instance.balanceOf.call(accounts[1]);
	assert(BN_transfer_amount.eq(a1_bal),
	       "post-transfer balance for 2nd account incorrect");

	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    let args = contract_events[tx_hash].args;
	    assert.equal(args.from, accounts[0],
			"Transfer event from wrong");
	    assert.equal(args.to, accounts[1],
			"Transfer event to wrong");
	    assert(args.tokens.eq(BN_transfer_amount),
		  "Transfer event amount of tokens wrong");
	}

	// transfer of too large amount should fail
	reverted = false;
	try {
	    result = await instance.transfer(account[1], BN_large_allowance, {from: accounts[0]});
	} catch (oops) {
	    reverted = true;
	}
	assert(reverted, "obscenely large transfer allowed?!?");
    })

    it("should handle escrow account creation", async () => {
	let instance = await Stake.deployed();

	let escrow_amount = 12345678;
	let BN_escrow_amount = web3.toBigNumber(escrow_amount);

	var escrow_id = -1;
	var result;
	var aux = 0xdeadbeef;

	var contract_events = {};
	var events;

	events = instance.EscrowCreate(
	    {},
	    {fromBlock: block_num + 1, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;
	});

	result = await instance.allocateEscrow(accounts[1],
					       BN_escrow_amount,
					       aux);
	events.stopWatching();

	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    let args = contract_events[tx_hash].args;
	    escrow_id = args.escrow_id;
	    assert.equal(args.owner, accounts[0],
			"EscrowCreate event owner wrong");
	    assert.equal(args.target, accounts[1],
			"EscrowCreate event target wrong");
	    assert(args.escrow_amount.eq(BN_escrow_amount),
		  "EscrowCreate event amount wrong");
	    assert.equal(args.aux, aux);
	}

	assert.notEqual(escrow_id, -1, "no event set the id");

	let decimals = await instance.decimals.call();
	let BN_decimals = web3.toBigNumber(decimals);
	var expected = (BN_initial_allocation
			.times(BN_10.pow(BN_decimals))
			.minus(BN_transfer_amount)
			.minus(BN_escrow_amount));

	var a0_bal = await instance.balanceOf.call(accounts[0]);
	assert(expected.eq(a0_bal),
	       "post-allocate available balance for 1st account wrong");

	var [bal, escrowed] = await instance.getStakeStatus.call(accounts[0]);
	expected = (BN_initial_allocation
		    .times(BN_10.pow(BN_decimals))
		    .minus(BN_transfer_amount));
	assert(expected.eq(bal), 
	       "post-allocate StakeStatus stake wrong");
	assert(BN_escrow_amount.eq(escrowed),
	       "post-allocate StakeStatus escrowed wrong");

	var a1_bal = await instance.balanceOf.call(accounts[1]);
	assert(BN_transfer_amount.eq(a1_bal),
	       "post-allocate available balance for 2nd account wrong");

	let escrow_to_take = 4321;
	let BN_escrow_to_take = web3.toBigNumber(escrow_to_take);

	contract_events = {};
	events = instance.EscrowClose(
	    {},
	    {fromBlock: 0, toBLock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	});

	var has_error = false;
	var seen_event = false;
	try {
	    let result = await instance.takeAndReleaseEscrow(escrow_id, BN_escrow_to_take);
	} catch (error) {
	    has_error = true;
	}
	assert(has_error, "Cannot take when not target of escrow"); // not owner

	events.stopWatching();

	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    seen_event = true;
	}
	assert(!seen_event,
	       ("Non-target takeAndReleaseEscrow should generate"
		+ " no EscrowClose events"));

	contract_events = {};
	events = instance.EscrowClose(
	    {},
	    {fromBlock: 0, toBLock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	});
	result = await instance.takeAndReleaseEscrow(escrow_id, BN_escrow_to_take, {from: accounts[1]});

	events.stopWatching();

	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    seen_event = true;
	    let args = contract_events[tx_hash].args;
	    assert(args.escrow_id.eq(web3.toBigNumber(escrow_id)));
	    assert.equal(args.aux, aux);
	    assert.equal(args.owner, accounts[0]);
	    assert(args.value_returned
		   .eq(BN_escrow_amount.minus(BN_escrow_to_take)));
	    assert.equal(args.target, accounts[1]);
	    assert(args.value_claimed.eq(BN_escrow_to_take));
	}
	assert(seen_event, "There should have been an EscrowClose event");

	a0_bal = await instance.balanceOf.call(accounts[0]);
	expected = (BN_initial_allocation
		    .times(BN_10.pow(BN_decimals))
		    .minus(BN_transfer_amount)
		    .minus(BN_escrow_to_take));
	assert(expected.eq(a0_bal),
	       "post-takeAndReleaseEscrow balance incorrect");

	[bal, escrowed] = await instance.getStakeStatus.call(accounts[0]);
	assert(expected.eq(bal),
	       "post-takeAndReleaseEscrow stakeStatus balance incorrect");
	assert.equal(escrowed.toNumber(), 0,
		    "post-takeAndReleaseEscrow stakeStatus escrow wrong");

	a1_bal = await instance.balanceOf.call(accounts[1]);
	assert(BN_transfer_amount.plus(BN_escrow_to_take).eq(a1_bal),
	       "post-takeAndReleaseEscrow target balance incorrect");
    })

    it("should handle approve", async () => {
	let instance = await Stake.deployed();

	var reverted;
	var result;
	var contract_events;
	var events;
	var args;
	var seen_event;
	var initial_stake_amount;
	var initial_escrow_amount;
	var initial_balanceOf_amount;  // available balance

	var stake_amount;
	var escrow_amount
	var available_balance;

	var initial_spend = Math.floor(small_allowance / 2);

	[initial_stake_amount, initial_escrow_amount] = await instance.getStakeStatus.call(accounts[0]);
	initial_balanceOf_amount = await instance.balanceOf.call(accounts[0]);
	assert(initial_stake_amount.minus(initial_escrow_amount).eq(initial_balanceOf_amount));

	reverted = false;
	contract_events = {};
	events = instance.Transfer({},{fromBlock: block_num + 1, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;
	});
	try {
	    result = await instance.transferFrom(accounts[0], accounts[2], BN_small_allowance,
						 {from: accounts[1]});
	} catch (oops) {
	    reverted = true;
	}
	events.stopWatching();
	assert(reverted, "Unauthorized transferFrom allowed");

	contract_events = {};
	events = instance.Approval({},{fromBlock: block_num + 1, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;
	});
	result = await instance.approve(accounts[1], BN_small_allowance);
	events.stopWatching();

	seen_event = false;
	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    if (contract_events[tx_hash].event != 'Approval') {
		continue;
	    }
	    seen_event = true;
	    args = contract_events[tx_hash].args;
	    assert.equal(args.tokenOwner, accounts[0]);
	    assert.equal(args.spender, accounts[1]);
	    assert(args.tokens.eq(BN_small_allowance));
	}
	assert(seen_event, "Approval event not generated.");

	assert(small_allowance <= initial_balanceOf_amount,
	       "Internal test error: allowance not small enough.");

	// check available stake hasn't changed.
	[stake_amount, escrow_amount] = await instance.getStakeStatus.call(accounts[0]);
	assert(stake_amount.eq(initial_stake_amount));
	assert(escrow_amount.eq(initial_escrow_amount));
	available_balance = await instance.balanceOf(accounts[0]);
	assert(available_balance.eq(initial_balanceOf_amount));

	contract_events = {};
	events = instance.Transfer({},{fromBlock: block_num + 1, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;
	});
	// use some approval amount; check event, balances.
	seen_event = false;
	result = await instance.transferFrom(accounts[0], accounts[2],
					     initial_spend, {from: accounts[1]});
	events.stopWatching();
	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    seen_event = true;
	    args = contract_events[tx_hash].args;
	    assert.equal(args.from, accounts[0]);
	    assert.equal(args.to, accounts[2]);
	    assert(args.tokens.eq(initial_spend));
	}
	assert(seen_event, "No Transfer event emitted");

	// check available stake has decreased by initial_spend
	[stake_amount, escrow_amount] = await instance.getStakeStatus.call(accounts[0]);
	assert(stake_amount.eq(initial_stake_amount.minus(initial_spend)));
	assert(escrow_amount.eq(initial_escrow_amount));
	available_balance = await instance.balanceOf(accounts[0]);
	assert(available_balance.plus(initial_spend).eq(initial_balanceOf_amount));

	// try to transfer too much; should fail.
	reverted = false;
	contract_events = {};
	events = instance.Transfer({},{fromBlock: block_num + 1, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;
	});
	try {
	    result = await instance.transferFrom(accounts[0], accounts[2],
						 BN_small_allowance.times(2),
						 {from: accounts[1]});
	} catch (oops) {
	    reverted = true;
	}
	events.stopWatching();
	assert(reverted, "Excessive transferFrom worked?!?");
	var num_events = 0;
	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    num_events++;
	}
	assert.equal(num_events, 0, "Excessive transferFrom should generate no events");

	// balances still only decreased by initial_spend
	[stake_amount, escrow_amount] = await instance.getStakeStatus.call(accounts[0]);
	assert(stake_amount.eq(initial_stake_amount.minus(initial_spend)));
	assert(escrow_amount.eq(initial_escrow_amount));
	available_balance = await instance.balanceOf(accounts[0]);
	assert(available_balance.plus(initial_spend).eq(initial_balanceOf_amount));

	// transfer the rest of the allowance
	contract_events = {};
	events = instance.Transfer({},{fromBlock: block_num + 1, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;
	});
	result = await instance.transferFrom(accounts[0], accounts[2],
					     BN_small_allowance.minus(initial_spend),
					     {from: accounts[1]});
	events.stopWatching();
	seen_event = false;
	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    let args = contract_events[tx_hash].args;
	    assert.equal(args.from, accounts[0]);
	    assert.equal(args.to, accounts[2]);
	    assert(args.tokens.eq(BN_small_allowance.minus(initial_spend)));
	    seen_event = true;
	}
	assert(seen_event, "Transfer event not generated for final transferFrom.");
    })
})
