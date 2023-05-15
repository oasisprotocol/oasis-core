package runtime

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// OffsetRestart is the offset restart scenario..
var OffsetRestart scenario.Scenario = newOffsetRestartImpl()

type offsetRestartImpl struct {
	RuntimeImpl
}

func newOffsetRestartImpl() scenario.Scenario {
	sc := &offsetRestartImpl{
		RuntimeImpl: *NewRuntimeImpl(
			"offset-restart",
			NewKVTestClient().WithScenario(InsertTransferKeyValueScenario),
		),
	}
	return sc
}

func (sc *offsetRestartImpl) Clone() scenario.Scenario {
	return &offsetRestartImpl{
		RuntimeImpl: *sc.RuntimeImpl.Clone().(*RuntimeImpl),
	}
}

func (sc *offsetRestartImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.RuntimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	f.Network.SetMockEpoch()

	// Make sure the compute nodes can terminate early.
	for i := range f.ComputeWorkers {
		f.ComputeWorkers[i].AllowEarlyTermination = true
	}

	return f, nil
}

func (sc *offsetRestartImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()
	if err := sc.StartNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	if _, err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}

	if err = sc.WaitTestClientOnly(); err != nil {
		return err
	}

	// Restart all compute workers.
	sc.Logger.Info("client done, restarting all compute workers")
	for _, compute := range sc.Net.ComputeWorkers() {
		if err = compute.Stop(); err != nil {
			return err
		}
	}
	for _, compute := range sc.Net.ComputeWorkers() {
		if err = compute.Start(); err != nil {
			return err
		}
	}
	for _, compute := range sc.Net.ComputeWorkers() {
		if err = compute.WaitReady(ctx); err != nil {
			return err
		}
	}

	// Try the client again. If the client node didn't reconnect to compute
	// nodes successfully again, the test should hang here. This specifically tests
	// earlier issues where the client node failed to reconnect to compute nodes
	// if these disconnected after the client node had already seen them, thereby
	// hanging the network (no transactions could be submitted).
	sc.Logger.Info("network back up, trying to run client again")
	sc.RuntimeImpl.testClient = NewKVTestClient().WithSeed("seed2").WithScenario(RemoveKeyValueScenario)
	return sc.RuntimeImpl.Run(childEnv)
}
