package e2e

import (
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/log"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

// TODO: Consider referencing script names directly from the Byzantine node.

var (
	// Permutations generated in the epoch 2 election are
	// compute:               3 (w), 0 (w), 2 (b), 1 (i)
	// transaction scheduler: 0 (w), 3 (i), 1 (i), 2 (i)
	// merge:                 1 (w), 2 (w), 0 (b), 3 (i)
	// w = worker; b = backup; i = invalid
	// For compute scripts, it suffices to be index 3.
	// For merge scripts, it suffices to be index 1.
	// No index is transaction scheduler only.
	// Indices are by order of node ID.

	// ByzantineComputeHonest is the byzantine compute honest scenario.
	ByzantineComputeHonest scenario.Scenario = newByzantineImpl("compute-honest", nil, oasis.ByzantineSlot3IdentitySeed)
	// ByzantineComputeWrong is the byzantine compute wrong scenario.
	ByzantineComputeWrong scenario.Scenario = newByzantineImpl("compute-wrong", []log.WatcherHandlerFactory{
		oasis.LogAssertNoTimeouts(),
		oasis.LogAssertNoRoundFailures(),
		oasis.LogAssertComputeDiscrepancyDetected(),
		oasis.LogAssertNoMergeDiscrepancyDetected(),
	}, oasis.ByzantineSlot3IdentitySeed)
	// ByzantineComputeStraggler is the byzantine compute straggler scenario.
	ByzantineComputeStraggler scenario.Scenario = newByzantineImpl("compute-straggler", []log.WatcherHandlerFactory{
		oasis.LogAssertTimeouts(),
		oasis.LogAssertNoRoundFailures(),
		oasis.LogAssertComputeDiscrepancyDetected(),
		oasis.LogAssertNoMergeDiscrepancyDetected(),
	}, oasis.ByzantineSlot3IdentitySeed)

	// ByzantineMergeHonest is the byzantine merge honest scenario.
	ByzantineMergeHonest scenario.Scenario = newByzantineImpl("merge-honest", nil, oasis.ByzantineSlot1IdentitySeed)
	// ByzantineMergeWrong is the byzantine merge wrong scenario.
	ByzantineMergeWrong scenario.Scenario = newByzantineImpl("merge-wrong", []log.WatcherHandlerFactory{
		oasis.LogAssertNoTimeouts(),
		oasis.LogAssertNoRoundFailures(),
		oasis.LogAssertNoComputeDiscrepancyDetected(),
		oasis.LogAssertMergeDiscrepancyDetected(),
	}, oasis.ByzantineSlot1IdentitySeed)
	// ByzantineMergeStraggler is the byzantine merge straggler scenario.
	ByzantineMergeStraggler scenario.Scenario = newByzantineImpl("merge-straggler", []log.WatcherHandlerFactory{
		oasis.LogAssertTimeouts(),
		oasis.LogAssertNoRoundFailures(),
		oasis.LogAssertNoComputeDiscrepancyDetected(),
		oasis.LogAssertMergeDiscrepancyDetected(),
	}, oasis.ByzantineSlot1IdentitySeed)
)

type byzantineImpl struct {
	basicImpl

	script                     string
	identitySeed               string
	logWatcherHandlerFactories []log.WatcherHandlerFactory
}

func newByzantineImpl(script string, logWatcherHandlerFactories []log.WatcherHandlerFactory, identitySeed string) scenario.Scenario {
	return &byzantineImpl{
		basicImpl: *newBasicImpl(
			"byzantine/"+script,
			"simple-keyvalue-ops-client",
			[]string{"set", "hello_key", "hello_value"},
		),
		script:                     script,
		identitySeed:               identitySeed,
		logWatcherHandlerFactories: logWatcherHandlerFactories,
	}
}

func (sc *byzantineImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// The byzantine node requires deterministic identities.
	f.Network.DeterministicIdentities = true
	// The byzantine scenario requires mock epochtime as the byzantine node
	// doesn't know how to handle epochs in which it is not scheduled.
	f.Network.EpochtimeMock = true
	// Change the default network log watcher handler factories if configured.
	if sc.logWatcherHandlerFactories != nil {
		f.Network.DefaultLogWatcherHandlerFactories = sc.logWatcherHandlerFactories
	}
	// Provision a Byzantine node.
	f.ByzantineNodes = []oasis.ByzantineFixture{
		oasis.ByzantineFixture{
			Script:          sc.script,
			IdentitySeed:    sc.identitySeed,
			Entity:          1,
			ActivationEpoch: 1,
		},
	}
	return f, nil
}

func (sc *byzantineImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.basicImpl.start(childEnv)
	if err != nil {
		return err
	}

	if err = sc.initialEpochTransitions(); err != nil {
		return err
	}

	return sc.wait(childEnv, cmd, clientErrCh)
}
