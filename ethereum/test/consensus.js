const Consensus = artifacts.require("Consensus");
const MockEpoch = artifacts.require("MockEpoch");
const crypto = require("crypto");
const truffleAssert = require('truffle-assertions');
const util = require("util");

contract("Ethereum Consensus test", async (accounts) => {
    // The test committee
    //
    // XXX: Eventually this will need an account that's neither the
    // owner nor in a committee, assuming that the contract will accept
    // commits/reveals/etc from the non-owner/leader to test access control.
    let owner = accounts[0];
    let leader = accounts[1];
    let workers = accounts.slice(2, 5);
    let backups = accounts.slice(6, 10);

    let epoch = 0xcafedeadbeef;

    function xor(a, b) {
        assert.equal(a.length, b.length, "length mismatch");
        let c = [];
        for (var i = 0; i < a.length; i++) {
            c.push(a[i] ^ b[i]);
        }
        return c;
    }

    function toHexString(b) {
        return "0x" + Buffer.from(b).toString("hex");
    }

    function ethSign(addr, hash) {
        let sig = web3.eth.sign(addr, hash);
        let r = sig.substr(0, 66);
        let s = "0x" + sig.substr(66, 64);
        let v = sig.substr(130, 2);
        return [r, s, v];
    }

    function makeCommitReveal(nodes, force_discrepancy) {
        if (force_discrepancy == undefined) {
            force_discrepancy = false;
        }
        let actual = [...crypto.randomBytes(32)];

        var reveals = [];
        var commits = [];

        var commit_sigs_r = [];
        var commit_sigs_s = [];
        var commit_sigs_v = "0x";

        var reveal_sigs_r = [];
        var reveal_sigs_s = [];
        var reveal_sigs_v = "0x";

        for (var i = 0; i < nodes.length; i++) {
            let addr = nodes[i];

            let raw_reveal = [...crypto.randomBytes(32)];
            var commit;
            if (force_discrepancy && i == nodes.length - 1) {
                // Force inject a discrepancy.
                commit = xor(actual, raw_reveal);
                commit[31] ^= 0x23;
            } else {
                commit = xor(actual, raw_reveal);
            }
            commit = toHexString(commit);
            let reveal = toHexString(raw_reveal);

            commits.push(commit);
            reveals.push(reveal);

            let commit_sig = ethSign(addr, commit);
            commit_sigs_r.push(commit_sig[0]);
            commit_sigs_s.push(commit_sig[1]);
            commit_sigs_v += commit_sig[2];

            let reveal_sig = ethSign(addr, reveal);
            reveal_sigs_r.push(reveal_sig[0]);
            reveal_sigs_s.push(reveal_sig[1]);
            reveal_sigs_v += reveal_sig[2];
        }

        let commit_sigs = [
            commit_sigs_r,
            commit_sigs_s,
            commit_sigs_v
        ];
        let reveal_sigs = [
            reveal_sigs_r,
            reveal_sigs_s,
            reveal_sigs_v
        ];

        return {
            "commits": commits,
            "reveals": reveals,
            "commit_signatures": commit_sigs,
            "reveal_signatures": reveal_sigs,
            "result": actual
        };
    }

    function assertRound(round, exp_epoch, exp_round, exp_leader) {
        assert.equal(round[0], exp_epoch, "unexpected round epoch");
        assert.equal(round[1], exp_round, "unexpected round counter");
        assert.equal(round[2], exp_leader, "unexpected leader");

        // This does not appear to give visibility into `workers`
        // `backups` and `commitments`. c'est la vie.
    }

    // New Committee.
    it("should accept a new committee from the owner", async () => {
        let instance = await Consensus.deployed();
        let epoch_instance = await MockEpoch.deployed();

        // Set the initial mock time.
        let epoch_res = await epoch_instance.set_epoch(epoch, 600);

        let res = await instance.new_committee(
            epoch,
            leader,
            workers,
            backups
        );

        let round = await instance.round.call();
        assertRound(round, epoch, 0, leader);
        let state = await instance.state.call();
        assert.equal(state, 1, "unexpected state");

        truffleAssert.eventEmitted(res, "OnWaitingCommitments", (ev) => {
            return ev._epoch == epoch &&
                ev._round == 0 &&
                ev._is_discrepancy_resolution == false;
        });
    })

    // Add Commitments/Add Reveals (fast path)
    it("should accept commits and reveals from the owner", async () => {
        let instance = await Consensus.deployed();

        let cr = makeCommitReveal(workers);

        let commit_res = await instance.add_commitments(
            cr["commit_signatures"][0],
            cr["commit_signatures"][1],
            cr["commit_signatures"][2],
            cr["commits"],
            { from: leader }
        );
        var state = await instance.state.call();
        assert.equal(state, 2, "unexpected state");

        truffleAssert.eventEmitted(commit_res, "OnWaitingReveals", (ev) => {
            return ev._epoch == epoch &&
                ev._round == 0 &&
                ev._is_discrepancy_resolution == false;
        });

        let reveal_res = await instance.add_reveals(
            cr["reveal_signatures"][0],
            cr["reveal_signatures"][1],
            cr["reveal_signatures"][2],
            cr["reveals"],
            { from: leader }
        );

        truffleAssert.eventEmitted(reveal_res, "OnFinalized", (ev) => {
            return ev._epoch == epoch &&
                ev._round == 0 &&
                ev._result == toHexString(cr["result"]);
        });

        // Automatically transitions back to WaitingCommitments after
        // finalization.
        truffleAssert.eventEmitted(reveal_res, "OnWaitingCommitments", (ev) => {
            return ev._epoch == epoch &&
                ev._round == 1 &&
                ev._is_discrepancy_resolution == false;
        });

        let round = await instance.round.call();
        assertRound(round, epoch, 1, leader);
        state = await instance.state.call();
        assert.equal(state, 1, "unexpected state");
    })

    // Discrepancy (mismatch).
    it("should fall back to the slow path on mismatch", async () => {
        let instance = await Consensus.deployed();

        // Fast path, with forced discrepancy.
        let fast_cr = makeCommitReveal(workers, true);

        let fast_commit_res = await instance.add_commitments(
            fast_cr["commit_signatures"][0],
            fast_cr["commit_signatures"][1],
            fast_cr["commit_signatures"][2],
            fast_cr["commits"],
            { from: leader }
        );
        var state = await instance.state.call();
        assert.equal(state, 2, "unexpected state");

        truffleAssert.eventEmitted(fast_commit_res, "OnWaitingReveals", (ev) => {
            return ev._epoch == epoch &&
                ev._round == 1 &&
                ev._is_discrepancy_resolution == false;
        });

        let fast_reveal_res = await instance.add_reveals(
            fast_cr["reveal_signatures"][0],
            fast_cr["reveal_signatures"][1],
            fast_cr["reveal_signatures"][2],
            fast_cr["reveals"],
            { from: leader }
        );
        state = await instance.state.call();
        assert.equal(state, 3, "unexpected state");

        truffleAssert.eventEmitted(fast_reveal_res, "OnWaitingCommitments", (ev) => {
            return ev._epoch == epoch &&
                ev._round == 1 &&
                ev._is_discrepancy_resolution == true;
        });

        // Slow path.
        let slow_cr = makeCommitReveal(backups, false);

        let slow_commit_res = await instance.add_commitments(
            slow_cr["commit_signatures"][0],
            slow_cr["commit_signatures"][1],
            slow_cr["commit_signatures"][2],
            slow_cr["commits"],
            { from: leader }
        );
        var state = await instance.state.call();
        assert.equal(state, 4, "unexpected state");

        truffleAssert.eventEmitted(slow_commit_res, "OnWaitingReveals", (ev) => {
            return ev._epoch == epoch &&
                ev._round == 1 &&
                ev._is_discrepancy_resolution == true;
        });

        let slow_reveal_res = await instance.add_reveals(
            slow_cr["reveal_signatures"][0],
            slow_cr["reveal_signatures"][1],
            slow_cr["reveal_signatures"][2],
            slow_cr["reveals"],
            { from: leader }
        );

        truffleAssert.eventEmitted(slow_reveal_res, "OnFinalized", (ev) => {
            return ev._epoch == epoch &&
                ev._round == 1 &&
                ev._result == toHexString(slow_cr["result"]);
        });

        // Automatically transitions back to WaitingCommitments after
        // finalization.
        truffleAssert.eventEmitted(slow_reveal_res, "OnWaitingCommitments", (ev) => {
            return ev._epoch == epoch &&
                ev._round == 2 &&
                ev._is_discrepancy_resolution == false;
        });

        let round = await instance.round.call();
        assertRound(round, epoch, 2, leader);
        state = await instance.state.call();
        assert.equal(state, 1, "unexpected state");
    })

    // New Committee (with existing).
    it("should accept a new committee from the leader", async () => {
        let instance = await Consensus.deployed();
        let epoch_instance = await MockEpoch.deployed();

        // Advance the mock time.
        let epoch_res = await epoch_instance.set_epoch(epoch+1, 600);

        let res = await instance.new_committee(
            epoch+1,
            owner,
            backups, // Flipped vs the initial committee.
            workers,
            { from: leader }
        );

        let round = await instance.round.call();
        assertRound(round, epoch+1, 0, owner);
        let state = await instance.state.call();
        assert.equal(state, 1, "unexpected state");

        truffleAssert.eventEmitted(res, "OnWaitingCommitments", (ev) => {
            return ev._epoch == epoch+1 &&
                ev._round == 0 &&
                ev._is_discrepancy_resolution == false;
        });
    })
})
