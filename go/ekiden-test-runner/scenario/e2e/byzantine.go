package e2e

import (
	"context"
	"fmt"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/ekiden"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/log"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/scenario"
	"github.com/oasislabs/ekiden/go/epochtime/tendermint_mock"
)

// TODO: Consider referencing script names directly from the Byzantine node.

const byzantineDefaultIdentitySeed = "ekiden byzantine node worker"

var (
	// ByzantineComputeHonest is the byzantine compute honest scenario.
	ByzantineComputeHonest scenario.Scenario = newByzantineImpl("compute-honest", nil)
	// ByzantineComputeWrong is the byzantine compute wrong scenario.
	ByzantineComputeWrong scenario.Scenario = newByzantineImpl("compute-wrong", []log.WatcherHandler{
		ekiden.LogAssertNoTimeouts(),
		ekiden.LogAssertNoRoundFailures(),
		ekiden.LogAssertComputeDiscrepancyDetected(),
		ekiden.LogAssertNoMergeDiscrepancyDetected(),
	})
	// ByzantineComputeStraggler is the byzantine compute straggler scenario.
	ByzantineComputeStraggler scenario.Scenario = newByzantineImpl("compute-straggler", []log.WatcherHandler{
		ekiden.LogAssertTimeouts(),
		ekiden.LogAssertNoRoundFailures(),
		ekiden.LogAssertComputeDiscrepancyDetected(),
		ekiden.LogAssertNoMergeDiscrepancyDetected(),
	})

	// ByzantineMergeHonest is the byzantine merge honest scenario.
	ByzantineMergeHonest scenario.Scenario = newByzantineImpl("merge-honest", nil)
	// ByzantineMergeWrong is the byzantine merge wrong scenario.
	ByzantineMergeWrong scenario.Scenario = newByzantineImpl("merge-wrong", []log.WatcherHandler{
		ekiden.LogAssertNoTimeouts(),
		ekiden.LogAssertNoRoundFailures(),
		ekiden.LogAssertNoComputeDiscrepancyDetected(),
		ekiden.LogAssertMergeDiscrepancyDetected(),
	})
	// ByzantineMergeStraggler is the byzantine merge straggler scenario.
	ByzantineMergeStraggler scenario.Scenario = newByzantineImpl("merge-straggler", []log.WatcherHandler{
		ekiden.LogAssertTimeouts(),
		ekiden.LogAssertNoRoundFailures(),
		ekiden.LogAssertNoComputeDiscrepancyDetected(),
		ekiden.LogAssertMergeDiscrepancyDetected(),
	})
)

type byzantineImpl struct {
	basicImpl

	script             string
	identitySeed       string
	logWatcherHandlers []log.WatcherHandler

	logger *logging.Logger
}

func newByzantineImpl(script string, logWatcherHandlers []log.WatcherHandler) scenario.Scenario {
	sc := &byzantineImpl{
		basicImpl: basicImpl{
			clientBinary: "simple-keyvalue-ops-client",
			clientArgs:   []string{"set", "hello_key", "hello_value"},
		},
		script:             script,
		identitySeed:       byzantineDefaultIdentitySeed,
		logWatcherHandlers: logWatcherHandlers,
		logger:             logging.GetLogger("scenario/e2e/byzantine/" + script),
	}
	return sc
}

func (sc *byzantineImpl) Name() string {
	return "byzantine/" + sc.script
}

func (sc *byzantineImpl) Fixture() (*ekiden.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// The byzantine node requires deterministic identities.
	f.Network.DeterministicIdentities = true
	// The byzantine scenario requires mock epochtime as the byzantine node
	// doesn't know how to handle epochs in which it is not scheduled.
	f.Network.EpochtimeBackend = tendermintmock.BackendName
	// Change the default log watcher handlers if configured.
	if sc.logWatcherHandlers != nil {
		f.Network.LogWatcherHandlers = sc.logWatcherHandlers
	}
	// Provision a Byzantine node.
	f.ByzantineNodes = []ekiden.ByzantineFixture{
		ekiden.ByzantineFixture{
			Script:       sc.script,
			IdentitySeed: sc.identitySeed,
			Entity:       1,
		},
	}
	return f, nil
}

func (sc *byzantineImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.basicImpl.start(childEnv)
	if err != nil {
		return err
	}

	// Wait for the nodes to register and then perform an epoch transition
	// as the byzantine node cannot handle intermediate epochs in which it
	// is not elected.
	sc.logger.Info("waiting for nodes to register",
		"num_nodes", sc.net.NumRegisterNodes(),
	)

	ctx := context.Background()
	if err = sc.net.Controller().WaitNodesRegistered(ctx, sc.net.NumRegisterNodes()); err != nil {
		return fmt.Errorf("failed to wait for nodes: %w", err)
	}

	sc.logger.Info("triggering epoch transition")
	if err = sc.net.Controller().SetEpoch(ctx, 1); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}
	sc.logger.Info("epoch transition done")

	return sc.wait(childEnv, cmd, clientErrCh)
}
