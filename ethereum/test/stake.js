const Stake = artifacts.require("Stake");

contract("Ethereum Stake test", async (accounts) => {
    let initial_allocation = 1;
    let transfer_amount = 1000;
    var BN_decimals = null;
    var BN_shift = null;
    let BN_initial_allocation = web3.toBigNumber(initial_allocation);
    let BN_transfer_amount = web3.toBigNumber(transfer_amount);
    let BN_10 = web3.toBigNumber(10);
    var BN_initial_tokens = null;
    let small_allowance = 4321;
    let BN_small_allowance = web3.toBigNumber(small_allowance);
    let BN_too_much = web3.toBigNumber(10).pow(web3.toBigNumber(20));
    var block_num = 0;

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
	BN_decimals = await instance.decimals.call();
	assert(BN_decimals.eq(18)); // matches contract
    })

    it("should have correct initial balance via getBalance", async () => {
	let instance = await Stake.deployed();
	let balance = await instance.balanceOf.call(accounts[0]);
	BN_shift = BN_10.pow(BN_decimals);
	BN_initial_tokens = BN_initial_allocation.times(BN_shift);
	assert(balance.eq(BN_initial_tokens), "Initial balance wrong");
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

	var a0_bal = await instance.balanceOf.call(accounts[0]);
	var expected = BN_initial_tokens.minus(BN_transfer_amount);
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
	    result = await instance.transfer(account[1], BN_too_much, {from: accounts[0]});
	} catch (oops) {
	    reverted = true;
	}
	assert(reverted, "obscenely large transfer allowed?!?");
    })

    function padHexStringTo64(s) {
	let slen = s.length;
	if (slen > 64) {
	    return "0x" + s.substr(0, 64);
	}
	let pad = 64 - slen;
	var v = [];
	v.length = pad;
	v.fill('0');
	var h = s + v.join('')
	return "0x" + h;
    }

    it("should handle escrow account creation", async () => {
	let instance = await Stake.deployed();

	let escrow_amount = 12345678;
	let BN_escrow_amount = web3.toBigNumber(escrow_amount);

	var escrow_id = -1;
	var result;
	var aux = padHexStringTo64('deadbeef');

	var contract_events = {};
	var events;

	events = instance.EscrowCreate(
	    {},
	    {fromBlock: block_num + 1, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;
		var args = result.args;
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

	// fetchEscrowById
	var [fetch_owner, fetch_target, fetch_amount, fetch_aux] = await instance.fetchEscrowById(escrow_id);
	assert.equal(fetch_owner, accounts[0]);
	assert.equal(fetch_target, accounts[1]);
	assert(fetch_amount.eq(BN_escrow_amount));
	assert.equal(fetch_aux, aux);

	var expected = (BN_initial_tokens
			.minus(BN_transfer_amount)
			.minus(BN_escrow_amount));

	var a0_bal = await instance.balanceOf.call(accounts[0]);
	assert(expected.eq(a0_bal),
	       "post-allocate available balance for 1st account wrong");

	var [bal, escrowed] = await instance.getStakeStatus.call(accounts[0]);
	expected = BN_initial_tokens.minus(BN_transfer_amount);
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
	expected = (BN_initial_tokens
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
	    seen_event = true;
	    args = contract_events[tx_hash].args;
	    assert.equal(args.tokenOwner, accounts[0]);
	    assert.equal(args.spender, accounts[1]);
	    assert(args.tokens.eq(BN_small_allowance));
	}
	assert(seen_event, "Approval event not generated.");

	// check allowance
	var read_allowance = await instance.allowance.call(accounts[0], accounts[1]);
	assert(BN_small_allowance.eq(read_allowance));

	assert(small_allowance <= initial_balanceOf_amount,
	       "Internal test error: allowance not small enough.");

	// check available stake hasn't changed.
	[stake_amount, escrow_amount] = await instance.getStakeStatus.call(accounts[0]);
	assert(stake_amount.eq(initial_stake_amount));
	assert(escrow_amount.eq(initial_escrow_amount));
	available_balance = await instance.balanceOf.call(accounts[0]);
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
	available_balance = await instance.balanceOf.call(accounts[0]);
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
	available_balance = await instance.balanceOf.call(accounts[0]);
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

	// balances updated by full allowance
	[stake_amount, escrow_amount] = await instance.getStakeStatus.call(accounts[0]);
	assert(stake_amount.eq(initial_stake_amount.minus(BN_small_allowance)));
	assert(escrow_amount.eq(initial_escrow_amount));
	available_balance = await instance.balanceOf.call(accounts[0]);
	assert(available_balance.plus(BN_small_allowance).eq(initial_balanceOf_amount));

	// allowance should be zero
	read_allowance = await instance.allowance.call(accounts[0], accounts[1]);
	assert(read_allowance.eq(0));

	// Crazy allowance:
	// BN_too_much is greater than available balance, which is allowed
	contract_events = {};
	events = instance.Approval({},{fromBlock: block_num + 1, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;
	});

	result = await instance.approve(accounts[1], BN_too_much);

	events.stopWatching();
	seen_event = false;
	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    seen_event = true;
	    args = contract_events[tx_hash].args;
	    assert.equal(args.tokenOwner, accounts[0]);
	    assert.equal(args.spender, accounts[1]);
	    assert(args.tokens.eq(BN_too_much));
	}
	assert(seen_event, "Approve BN_too_much event not generated.");

	// allowance should be BN_too_much
	read_allowance = await instance.allowance.call(accounts[0], accounts[1]);
	assert(read_allowance.eq(BN_too_much));

	// Set allowance to zero.
	contract_events = {};
	events = instance.Approval({},{fromBlock: block_num + 1, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;
	});

	result = await instance.approve(accounts[1], 0);

	events.stopWatching();
	seen_event = false;
	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    seen_event = true;
	    args = contract_events[tx_hash].args;
	    assert.equal(args.tokenOwner, accounts[0]);
	    assert.equal(args.spender, accounts[1]);
	    assert(args.tokens.eq(0));
	}
	assert(seen_event, "Approve zero event not generated.");
    })

    it("should burn! burn!", async() => {
	let instance = await Stake.deployed();

	var initial_stake_amount;
	var initial_escrow_amount;
	var initial_balanceOf_amount;  // available balance
	var result;
	var burn_amount = web3.toBigNumber(123);
	var initial_supply;

	var reverted;
	var contract_events;
	var events;
	var args;

	var stake_amount;
	var escrow_amount
	var available_balance;

	initial_supply = await instance.totalSupply();

	[initial_stake_amount, initial_escrow_amount] = await instance.getStakeStatus.call(accounts[0]);
	initial_balanceOf_amount = await instance.balanceOf.call(accounts[0]);
	assert(initial_stake_amount.minus(initial_escrow_amount).eq(initial_balanceOf_amount));

	assert(initial_balanceOf_amount.lt(BN_too_much),
	       "test internal error: BN_too_much not too much!?!");

	reverted = false;
	try {
	    result = await instance.burn(BN_too_much);
	} catch (oops) {
	    reverted = true;
	}
	assert(reverted, "burn token quantity larger than balance should have failed");

	reverted = false;
	try {
	    result = await instance.burn(initial_balanceOf_amount.plus(1));
	} catch (oops) {
	    reverted = true;
	}
	assert(reverted, "burn token quantity one larger than available balance succeeded?!?");

	contract_events = {};
	events = instance.Burn({},{fromBlock: block_num + 1, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;
	});

	result = await instance.burn(burn_amount);

	events.stopWatching();
	seen_event = false;
	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    seen_event = true;
	    args = contract_events[tx_hash].args;
	    assert.equal(args.from, accounts[0]);
	    assert(args.value.eq(burn_amount));
	}
	assert(seen_event, "Burn event not generated.");

	[stake_amount, escrow_amount] = await instance.getStakeStatus.call(accounts[0]);
	assert(stake_amount.eq(initial_stake_amount.minus(burn_amount)));
	assert(escrow_amount.eq(initial_escrow_amount));
	available_balance = await instance.balanceOf.call(accounts[0]);
	assert(available_balance.eq(initial_balanceOf_amount.minus(burn_amount)));

	assert(initial_supply.minus(burn_amount).eq(await instance.totalSupply()));
    });

    it("should burn from afar!", async() => {
	let instance = await Stake.deployed();

	var initial_stake_amount;
	var initial_escrow_amount;
	var initial_balanceOf_amount;  // available balance
	var result;
	var burn_amount = web3.toBigNumber(31415);
	var initial_supply;

	var contract_events;
	var events;
	var args;

	var stake_amount;
	var escrow_amount
	var available_balance;

	initial_supply = await instance.totalSupply();

	[initial_stake_amount, initial_escrow_amount] = await instance.getStakeStatus.call(accounts[0]);
	initial_balanceOf_amount = await instance.balanceOf.call(accounts[0]);
	assert(initial_stake_amount.minus(initial_escrow_amount).eq(initial_balanceOf_amount));

	reverted = false;
	try {
	    result = await instance.burnFrom(accounts[0], BN_too_much, {from: accounts[1]});
	} catch (oops) {
	    reverted = true;
	}
	assert(reverted, "other: burn token quantity larger than balance should have failed");

	reverted = false;
	try {
	    result = await instance.burnFrom(accounts[0], initial_balanceOf_amount.plus(1),
					     {from: accounts[1]});
	} catch (oops) {
	    reverted = true;
	}
	assert(reverted, "other: burn token quantity one larger than available balance succeeded?!?");

	contract_events = {};
	events = instance.Approval({},{fromBlock: block_num + 1, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;
	});

	result = await instance.approve(accounts[1], burn_amount);

	events.stopWatching();
	seen_event = false;
	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    seen_event = true;
	    args = contract_events[tx_hash].args;
	    assert.equal(args.tokenOwner, accounts[0]);
	    assert.equal(args.spender, accounts[1]);
	    assert(args.tokens.eq(burn_amount));
	}
	assert(seen_event, "Approve event not generated.");

	reverted = false;
	try {
	    result = await instance.burnFrom(accounts[0], BN_too_much, {from: accounts[1]});
	} catch (oops) {
	    reverted = true;
	}
	assert(reverted, "burnFrom token quantity larger than approval should have failed");

	reverted = false;
	try {
	    result = await instance.burnFrom(accounts[0], burn_amount.plus(1),
					     {from: accounts[1]});
	} catch (oops) {
	    reverted = true;
	}
	assert(reverted, "burnFrom token quantity one larger than approval succeeded?!?");

	reverted = false;
	try {
	    result = await instance.burnFrom(accounts[0], burn_amount,
					     {from: accounts[2]});
	} catch (oops) {
	    reverted = true;
	}
	assert(reverted, "burnFrom correct amount but not allowance account?!?");

	contract_events = {};
	events = instance.Burn({},{fromBlock: block_num + 1, toBlock: "latest"});
	events.watch(function(error, result) {
	    assert.isNull(error, "Event error: " + error);
	    contract_events[result.transactionHash] = result;
	    block_num = result.blockNumber;
	});

	result = await instance.burnFrom(accounts[0], burn_amount, {from: accounts[1]});

	events.stopWatching();
	seen_event = false;
	for (var tx_hash in contract_events) {
	    if (!contract_events.hasOwnProperty(tx_hash)) {
		continue;
	    }
	    seen_event = true;
	    args = contract_events[tx_hash].args;
	    assert.equal(args.from, accounts[0]);
	    assert(args.value.eq(burn_amount));
	}
	assert(seen_event, "Burn event not generated.");

	[stake_amount, escrow_amount] = await instance.getStakeStatus.call(accounts[0]);
	assert(stake_amount.eq(initial_stake_amount.minus(burn_amount)));
	assert(escrow_amount.eq(initial_escrow_amount));
	available_balance = await instance.balanceOf.call(accounts[0]);
	assert(available_balance.eq(initial_balanceOf_amount.minus(burn_amount)));

	assert(initial_supply.minus(burn_amount).eq(await instance.totalSupply()));
    });

    it("should iterate through escrow accounts", async () => {
	let instance = await Stake.deployed();

	var record_size = 3;
	var test_info = [
	    accounts[1], 1234,       padHexStringTo64("deadbeef"),
	    accounts[1], 31415926,   padHexStringTo64("cafebabe"),
	    accounts[0], 2718281828, padHexStringTo64("babedead"),
	    accounts[2], 2345,       padHexStringTo64("beef"),
	    accounts[2], 5432,       padHexStringTo64("aced"),
	    accounts[1], 420,        padHexStringTo64("ac1dbabe"),
	];
	var result;
	var seen = Array(test_info.length / record_size).fill(false);
	var escrow_ids = [];
	var num_tests = seen.length;
	var has_next, state;
	var id, target, amt, aux;

	assert.equal(test_info.length, record_size * num_tests);
	for (var entry = 0; entry < num_tests; ++entry) {
	    var acct = test_info[record_size * entry + 0];
	    var amt  = test_info[record_size * entry + 1];
	    var aux  = test_info[record_size * entry + 2];

	    // gross
	    escrow_ids.push(await instance.allocateEscrow.call(acct, amt, aux));
	    result = await instance.allocateEscrow(acct, amt, aux);
	}

	[has_next, state] = await instance.listActiveEscrowsIterator(accounts[0]);
	while (has_next) {
	    [id, target, amt, aux, has_next, state] = await instance.listActiveEscrowsGet(
		accounts[0], state);

	    var matched = false;
	    for (var entry = 0; entry < num_tests; ++entry) {
		if (target == test_info[record_size * entry + 0] &&
		    amt.eq(test_info[record_size * entry + 1]) &&
		    aux == test_info[record_size * entry + 2]) {
		    assert(!seen[entry], "an escrow account was listed twice");
		    seen[entry] = true;
		    matched = true;
		    break;
		}
	    }
	    assert(matched, "escrow account not created by the test: id = " + id + ", target = " + target + ", amt = " + amt + ", aux = " + aux);
	    // leftover from a previous test?!?
	}
	for (var entry = 0; entry < num_tests; ++entry) {
	    assert(seen[entry], "an escrow account was not enumerated! (#" + entry + ")");
	}

	// cleanup -- get rid of the escrow accounts so if we add more
	// tests later state is relatively clean.
	for (var entry = 0; entry < num_tests; ++entry) {
	    result = await instance.takeAndReleaseEscrow(
		escrow_ids[entry], web3.toBigNumber(0),
		{from: test_info[record_size * entry + 0]});
	}
    });
})
