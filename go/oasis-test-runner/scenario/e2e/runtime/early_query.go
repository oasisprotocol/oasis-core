package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
)

var (
	// EarlyQuery is the early query scenario where we query a validator node before the network
	// has started and there are no committed blocks.
	EarlyQuery scenario.Scenario = &earlyQueryImpl{
		Scenario: e2e.NewScenario("early-query"),
	}

	// EarlyQueryInitHeight is the same as EarlyQuery scenario but with an initial height set.
	EarlyQueryInitHeight scenario.Scenario = &earlyQueryImpl{
		Scenario:      e2e.NewScenario("early-query/init-height"),
		initialHeight: 42,
	}

	// EarlyQueryRuntime is the early query scenario where we query a runtime node.
	EarlyQueryRuntime scenario.Scenario = &earlyQueryImpl{
		Scenario: NewScenario("early-query", nil),
		runtime:  true,
	}
)

type earlyQueryImpl struct {
	scenario.Scenario

	runtime       bool
	initialHeight int64
}

func (sc *earlyQueryImpl) Clone() scenario.Scenario {
	return &earlyQueryImpl{
		Scenario:      sc.Scenario.Clone(),
		runtime:       sc.runtime,
		initialHeight: sc.initialHeight,
	}
}

func (sc *earlyQueryImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	f.Network.SetInsecureBeacon()

	// Set initial height.
	f.Network.InitialHeight = sc.initialHeight

	// Only one validator should actually start to prevent the network from committing any blocks.
	f.Validators[1].NoAutoStart = true
	f.Validators[2].NoAutoStart = true

	return f, nil
}

func (sc *earlyQueryImpl) Run(ctx context.Context, _ *env.Env) error {
	// Start the network.
	var err error
	if err = sc.Network().Start(); err != nil {
		return err
	}

	var ctrl *oasis.Controller
	switch sc.runtime {
	case false:
		ctrl = sc.Network().Controller()
	case true:
		// Use the compute worker node in the runtime scenario.
		ctrl, err = oasis.NewController(sc.Network().ComputeWorkers()[0].SocketPath())
		if err != nil {
			return fmt.Errorf("failed to create controller for compute node: %w", err)
		}

	}

	// Perform consensus queries.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// StateToGenesis.
	_, err = ctrl.Consensus.StateToGenesis(ctx, consensus.HeightLatest)
	if !errors.Is(err, consensus.ErrNoCommittedBlocks) {
		return fmt.Errorf("StateToGenesis query should fail with ErrNoCommittedBlocks (got: %s)", err)
	}
	// GetBlock.
	_, err = ctrl.Consensus.GetBlock(ctx, consensus.HeightLatest)
	if !errors.Is(err, consensus.ErrNoCommittedBlocks) {
		return fmt.Errorf("GetBlock query should fail with ErrNoCommittedBlocks (got: %s)", err)
	}
	// GetTransactions.
	_, err = ctrl.Consensus.GetTransactions(ctx, consensus.HeightLatest)
	if !errors.Is(err, consensus.ErrNoCommittedBlocks) {
		return fmt.Errorf("GetTransactions query should fail with ErrNoCommittedBlocks (got: %s)", err)
	}
	// GetTransactionsWithResults.
	_, err = ctrl.Consensus.GetTransactionsWithResults(ctx, consensus.HeightLatest)
	if !errors.Is(err, consensus.ErrNoCommittedBlocks) {
		return fmt.Errorf("GetTransactionsWithResults query should fail with ErrNoCommittedBlocks (got: %s)", err)
	}

	switch sc.runtime {
	case false:
		// GetStatus on validator.
		status, err := ctrl.GetStatus(ctx)
		if err != nil {
			return fmt.Errorf("failed to get status for node: %w", err)
		}
		if status.Consensus.Status != consensus.StatusStateSyncing {
			return fmt.Errorf("node reports as ready before chain is initialized")
		}
		if status.Consensus.LatestHeight != 0 {
			return fmt.Errorf("node reports non-zero latest height before chain is initialized")
		}
		if !status.Consensus.IsValidator {
			return fmt.Errorf("node does not report itself to be a validator at genesis")
		}
	case true:
		// GetStatus on a compute node.
		status, err := ctrl.GetStatus(ctx)
		if err != nil {
			return fmt.Errorf("failed to get status for compute node: %w", err)
		}
		fmt.Println(status)
		if status.Consensus.Status != consensus.StatusStateSyncing {
			return fmt.Errorf("node reports as ready before chain is initialized")
		}
		if status.Consensus.LatestHeight != 0 {
			return fmt.Errorf("node reports non-zero latest height before chain is initialized")
		}
		if status.Consensus.IsValidator {
			return fmt.Errorf("compute node does report itself to be a validator at genesis")
		}
		if len(status.Runtimes) < 1 {
			return fmt.Errorf("compute node status does not contain any runtimes")
		}
	}

	return nil
}
