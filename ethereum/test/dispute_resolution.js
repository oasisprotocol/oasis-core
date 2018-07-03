const DisputeResolution = artifacts.require("DisputeResolution");
const crypto = require("crypto");
const truffleAssert = require("truffle-assertions");
const util = require("util");

contract("Dispute Resolution test", async (accounts) => {
	let empty_addr = "0x0000000000000000000000000000000000000000";
	let empty_hash = "0x0000000000000000000000000000000000000000000000000000000000000000";

	let owner = accounts[0];
	var workers = accounts.slice(1, 5);
	var backups = accounts.slice(6, 10);

	var serial = 0;
	var batch_hash;

	function ethSign(addr, hash) {
		let sig = web3.eth.sign(addr, hash);
		let r = sig.substr(0, 66);
		let s = "0x" + sig.substr(66, 64);
		let v = sig.substr(130, 2);
		return [r, s, v];
	}

	function toHexString(b) {
		return "0x" + Buffer.from(b).toString("hex");
	}

	function randomBytes(size) {
		return toHexString(crypto.randomBytes(size));
	}

	function assertTransitionOk(state, committee) {
		assert.equal(state, 1, "unexpected state");
		assert.equal(committee[0], empty_addr, "invalid dispute_sender");
		assert.equal(committee[1], empty_hash, "invalid dispute_batch_hash");
		assert.equal(committee[2], serial + 1, "invalid serial");
	}

	// Bootstrap committee.
	it("should accept a new committee from the owner", async () => {
		let instance = await DisputeResolution.deployed();

		// Generate a random initial root hash.
		let root_hash = randomBytes(32);

		let res = await instance.transition(
			workers,
			backups,
			root_hash,
			[], [], "", // No committee, no signatures.
			{ from: owner }
		);

		let state = await instance.state.call();
		let committee = await instance.committee.call();
		assertTransitionOk(state, committee);

		truffleAssert.eventEmitted(res, "OnTransition", (ev) => {
			return ev._serial == serial && ev._finalized_root_hash == root_hash;
		});

		serial = serial + 1;
	})

	// Optimistic transition.
	it("should transition in the optimisic path", async () => {
		let instance = await DisputeResolution.deployed();

		// Generate the next root hash.
		let root_hash = randomBytes(32);

		// "Generate" the new committee.
		let new_workers = backups;
		let new_backups = workers;

		// Derive the digest that each worker would, to sign for the
		// transition.
		let digest = await instance.derive_transition_digest.call(
			serial,
			new_workers,
			new_backups,
			root_hash
		);

		// Sign the digest with each worker.
		var sigs_r = [];
		var sigs_s = [];
		var sigs_v = "0x";
		for (let addr of workers) {
			let sig = ethSign(addr, digest);
			sigs_r.push(sig[0]);
			sigs_s.push(sig[1]);
			sigs_v += sig[2];
		}

		let res = await instance.transition(
			new_workers,
			new_backups,
			root_hash,
			sigs_r,
			sigs_s,
			sigs_v,
			{ from: workers[0] }
		);

		let state = await instance.state.call();
		let committee = await instance.committee.call();
		assertTransitionOk(state, committee);

		truffleAssert.eventEmitted(res, "OnTransition", (ev) => {
			return ev._serial == serial && ev._finalized_root_hash == root_hash;
		});

		serial = serial + 1;
		workers = new_workers;
		backups = new_backups;
	});

	// Dispute.
	it("should accept a dispute from a worker", async () => {
		let instance = await DisputeResolution.deployed();

		// Generate the batch hash for this dispute.
		batch_hash = randomBytes(32);

		var reveals = [];
		var sigs_r = [];
		var sigs_s = [];
		var sigs_v = "0x";
		for (let addr of workers) {
			let reveal = randomBytes(32);
			let digest = await instance.derive_reveal_digest.call(
				serial,
				batch_hash,
				reveal
			);
			reveals.push(reveal);

			let sig = ethSign(addr, digest);
			sigs_r.push(sig[0]);
			sigs_s.push(sig[1]);
			sigs_v += sig[2];
		}

		let res = await instance.dispute(
			batch_hash,
			reveals,
			sigs_r,
			sigs_s,
			sigs_v,
			{ from: workers[1] }
		);

		let state = await instance.state.call();
		assert.equal(state,  2, "unexpected state");
		let committee = await instance.committee.call();
		assert.equal(committee[0], workers[1], "invalid dispute_sender");
		assert.equal(committee[1], batch_hash, "invalid dispute_batch_hash");

		truffleAssert.eventEmitted(res, "OnDispute", (ev) => {
			return ev._batch_hash == batch_hash;
		});
	});

	// Resolve.
	it("should accept a resolution from a backup", async () => {
		let instance = await DisputeResolution.deployed();

		// Generate the "correct" reveal, current contract requires
		// total consensus amongst backups.
		let reveal = randomBytes(32);
		let digest = await instance.derive_reveal_digest.call(
			serial,
			batch_hash,
			reveal
		);

		var reveals = [];
		var sigs_r = [];
		var sigs_s = [];
		var sigs_v = "0x";
		for (let addr of backups) {
			reveals.push(reveal);

			let sig = ethSign(addr, digest);
			sigs_r.push(sig[0]);
			sigs_s.push(sig[1]);
			sigs_v += sig[2];
		}

		let res = await instance.resolve_dispute(
			reveals,
			sigs_r,
			sigs_s,
			sigs_v,
			{ from: backups[0] }
		);

		truffleAssert.eventEmitted(res, "OnDisputeResolution", (ev) => {
			return ev._batch_hash == batch_hash && ev._value == reveal;
		})

		// Ensure that the contract is back to the optimistic path.
		let state = await instance.state.call();
		assert.equal(state, 1, "unexpected state");
		let committee = await instance.committee.call();
		assert.equal(committee[0], empty_addr, "invalid dispute_sender");
		assert.equal(committee[1], empty_hash, "invalid dispute_batch_hash");
	});

	// TODO: Test all the various failure cases.
})