package runtime

import (
	"strconv"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/byzantine"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// Permutations generated in the epoch 2 election are
	// executor:                   3 (w+s), 0 (w), 2 (b), 1 (i)
	// storage (default fixture):  0   (w), 1 (w), 2 (i), 3 (i)
	// w = worker and not scheduler in first round
	// w+s = worker and scheduler in first round
	// b = backup
	// i = invalid
	//
	//
	// For executor scripts, it suffices to be index 0.
	// For executor and scheduler scripts, it suffices to be index 3.
	// For storage worker scripts suffices to be index 0.

	// ByzantineExecutorHonest is the byzantine executor honest scenario.
	ByzantineExecutorHonest scenario.Scenario = newByzantineImpl(
		"executor-honest",
		"executor",
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		nil,
	)
	// ByzantineExecutorSchedulerHonest is the byzantine executor scheduler honest scenario.
	ByzantineExecutorSchedulerHonest scenario.Scenario = newByzantineImpl(
		"executor-scheduler-honest",
		"executor",
		nil,
		oasis.ByzantineSlot3IdentitySeed,
		[]string{
			"--" + byzantine.CfgSchedulerRoleExpected,
		},
	)
	// ByzantineExecutorWrong is the byzantine executor wrong scenario.
	ByzantineExecutorWrong scenario.Scenario = newByzantineImpl(
		"executor-wrong",
		"executor",
		[]log.WatcherHandlerFactory{
			// Wrong commitment should trigger discrepancy detection, but the round shouldn't fail.
			oasis.LogAssertNoTimeouts(),
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		[]string{
			"--" + byzantine.CfgExecutorMode, byzantine.ModeExecutorWrong.String(),
		},
	)
	// ByzantineExecutorSchedulerWrong is the byzantine executor wrong scheduler scenario.
	ByzantineExecutorSchedulerWrong scenario.Scenario = newByzantineImpl(
		"executor-scheduler-wrong",
		"executor",
		[]log.WatcherHandlerFactory{
			// Invalid proposed batch should trigger round failure in first round (proposer timeout).
			// In round two timeout and discrepancy detection should be triggered.
			oasis.LogAssertRoundFailures(),
			oasis.LogAssertTimeouts(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineSlot3IdentitySeed,
		[]string{
			"--" + byzantine.CfgSchedulerRoleExpected,
			"--" + byzantine.CfgExecutorMode, byzantine.ModeExecutorWrong.String(),
		},
	)
	// ByzantineExecutorStraggler is the byzantine executor straggler scenario.
	ByzantineExecutorStraggler scenario.Scenario = newByzantineImpl(
		"executor-straggler",
		"executor",
		[]log.WatcherHandlerFactory{
			// Straggler should trigger timeout and discrepancy detection, but the round shouldn't fail.
			oasis.LogAssertTimeouts(),
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		[]string{
			"--" + byzantine.CfgExecutorMode, byzantine.ModeExecutorStraggler.String(),
		},
	)
	// ByzantineExecutorSchedulerStraggler is the byzantine executor scheduler straggler scenario.
	ByzantineExecutorSchedulerStraggler scenario.Scenario = newByzantineImpl(
		"executor-scheduler-straggler",
		"executor",
		[]log.WatcherHandlerFactory{
			// Scheduler straggler should trigger round failure in first round (proposer timeout).
			// In round two timeout and discrepancy detection should be triggered.
			oasis.LogAssertRoundFailures(),
			oasis.LogAssertTimeouts(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineSlot3IdentitySeed,
		[]string{
			"--" + byzantine.CfgSchedulerRoleExpected,
			"--" + byzantine.CfgExecutorMode, byzantine.ModeExecutorStraggler.String(),
		},
	)
	// ByzantineExecutorFailureIndicating is the byzantine executor that submits fialure indicating
	// commitments scenario.
	ByzantineExecutorFailureIndicating scenario.Scenario = newByzantineImpl(
		"executor-failure-indicating",
		"executor",
		[]log.WatcherHandlerFactory{
			// Failure indicating executor should trigger discrepancy detection, but the round shouldn't fail.
			oasis.LogAssertNoTimeouts(),
			oasis.LogAssertNoRoundFailures(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		[]string{
			"--" + byzantine.CfgExecutorMode, byzantine.ModeExecutorFailureIndicating.String(),
		},
	)
	// ByzantineExecutorSchedulerFailureIndicating is the byzantine executor scheduler failure indicating scenario.
	ByzantineExecutorSchedulerFailureIndicating scenario.Scenario = newByzantineImpl(
		"executor-scheduler-failure-indicating",
		"executor",
		[]log.WatcherHandlerFactory{
			// Failure indicating scheduler submitts a failure indicating commitment and doesn't propagate the batch.
			// This triggers a timeout, discrepancy detection and results in round failure.
			oasis.LogAssertRoundFailures(),
			oasis.LogAssertTimeouts(),
			oasis.LogAssertExecutionDiscrepancyDetected(),
		},
		oasis.ByzantineSlot3IdentitySeed,
		[]string{
			"--" + byzantine.CfgSchedulerRoleExpected,
			"--" + byzantine.CfgExecutorMode, byzantine.ModeExecutorFailureIndicating.String(),
		},
	)
	// ByzantineStorageHonest is the byzantine storage honest scenario.
	ByzantineStorageHonest scenario.Scenario = newByzantineImpl(
		"storage-honest",
		"storage",
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		nil,
	)
	// ByzantineStorageFailApply is the byzantine storage scenario where storage node fails
	// first 5 Apply requests.
	ByzantineStorageFailApply scenario.Scenario = newByzantineImpl(
		"storage-fail-apply",
		"storage",
		// Failing first 5 apply requests should result in no round failures. As the proposer
		// should keep retrying proposing a batch until it succeeds.
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		[]string{
			// Fail first 5 ApplyBatch requests.
			"--" + byzantine.CfgNumStorageFailApply, strconv.Itoa(5),
		},
	)
	// ByzantineStorageFailApplyBatch is the byzantine storage scenario where storage node fails
	// first 3 ApplyBatch requests.
	ByzantineStorageFailApplyBatch scenario.Scenario = newByzantineImpl(
		"storage-fail-applybatch",
		"storage",
		[]log.WatcherHandlerFactory{
			// There should be a discrepancy. Discrepancy resolution should fail with majority failure.
			oasis.LogAssertExecutionDiscrepancyDetected(),
			oasis.LogAssertDiscrepancyMajorityFailure(),
			oasis.LogAssertRoundFailures(),
		},
		oasis.ByzantineDefaultIdentitySeed,
		[]string{
			// Fail first 3 ApplyBatch requests - from the 2 executor workers and 1 backup node.
			"--" + byzantine.CfgNumStorageFailApplyBatch, strconv.Itoa(3),
		},
	)
	// ByzantineStorageFailRead is the byzantine storage node scenario that fails all read requests.
	ByzantineStorageFailRead scenario.Scenario = newByzantineImpl(
		"storage-fail-read",
		"storage",
		// There should be no discrepancy or round failrues.
		nil,
		oasis.ByzantineDefaultIdentitySeed,
		[]string{
			// Fail all read requests.
			"--" + byzantine.CfgFailReadRequests,
		},
	)
)

type byzantineImpl struct {
	runtimeImpl

	script    string
	extraArgs []string

	identitySeed               string
	logWatcherHandlerFactories []log.WatcherHandlerFactory
}

func newByzantineImpl(
	name string,
	script string,
	logWatcherHandlerFactories []log.WatcherHandlerFactory,
	identitySeed string,
	extraArgs []string,
) scenario.Scenario {
	return &byzantineImpl{
		runtimeImpl: *newRuntimeImpl(
			"byzantine/"+name,
			"simple-keyvalue-ops-client",
			[]string{"set", "hello_key", "hello_value"},
		),
		script:                     script,
		extraArgs:                  extraArgs,
		identitySeed:               identitySeed,
		logWatcherHandlerFactories: logWatcherHandlerFactories,
	}
}

func (sc *byzantineImpl) Clone() scenario.Scenario {
	return &byzantineImpl{
		runtimeImpl:                *sc.runtimeImpl.Clone().(*runtimeImpl),
		script:                     sc.script,
		extraArgs:                  sc.extraArgs,
		identitySeed:               sc.identitySeed,
		logWatcherHandlerFactories: sc.logWatcherHandlerFactories,
	}
}

func (sc *byzantineImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// The byzantine node requires deterministic identities.
	f.Network.DeterministicIdentities = true
	// The byzantine scenario requires mock epochtime as the byzantine node
	// doesn't know how to handle epochs in which it is not scheduled.
	f.Network.SetMockEpoch()
	// Change the default network log watcher handler factories if configured.
	if sc.logWatcherHandlerFactories != nil {
		f.Network.DefaultLogWatcherHandlerFactories = sc.logWatcherHandlerFactories
	}
	// Provision a Byzantine node.
	f.ByzantineNodes = []oasis.ByzantineFixture{
		{
			Script:          sc.script,
			ExtraArgs:       sc.extraArgs,
			IdentitySeed:    sc.identitySeed,
			Entity:          1,
			ActivationEpoch: 1,
		},
	}
	return f, nil
}

func (sc *byzantineImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.runtimeImpl.start(childEnv)
	if err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	if err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}

	return sc.wait(childEnv, cmd, clientErrCh)
}
