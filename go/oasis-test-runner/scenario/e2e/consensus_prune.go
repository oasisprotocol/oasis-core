package e2e

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const (
	pruneNumKept = 20
)

// ConsensusPrune is scenario that tests consensus block pruning.
var ConsensusPrune scenario.Scenario = &consensusPruneImpl{
	Scenario: *NewScenario("consensus-prune"),
}

type consensusPruneImpl struct {
	Scenario
}

func (sc *consensusPruneImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	f.Validators[0].Consensus.PruneNumKept = pruneNumKept
	f.Validators[0].LogWatcherHandlerFactories = []log.WatcherHandlerFactory{
		// Ensure ABCI pruning happens on the node.
		oasis.LogEventABCIPruneDelete(),
	}

	return f, nil
}

func (sc *consensusPruneImpl) Clone() scenario.Scenario {
	return &consensusPruneImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *consensusPruneImpl) Run(ctx context.Context, _ *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return fmt.Errorf("failed to start network: %w", err)
	}

	// Wait first few blocks and ensure no pruning.
	halfPrune := pruneNumKept / 2
	if _, err := sc.WaitBlocks(ctx, halfPrune); err != nil {
		return fmt.Errorf("failed waiting %d blocks: %w", halfPrune, err)
	}

	sc.Logger.Info("ensure no pruning",
		"start_height", 1,
		"end_height", halfPrune,
	)
	ctrl := sc.Net.Controller()
	for h := 1; h <= halfPrune; h++ {
		if _, err := ctrl.Consensus.GetBlock(ctx, int64(h)); err != nil {
			return fmt.Errorf("pruning too early: %w", err)
		}
	}

	// Wait for additional blocks and verify pruning.
	if _, err := sc.WaitBlocks(ctx, pruneNumKept); err != nil {
		return fmt.Errorf("failed waiting for %d blocks: %w", 2*pruneNumKept, err)
	}

	// Give pruner, which triggers every second, enough time to prune.
	time.Sleep(5 * time.Second)

	sc.Logger.Info("ensure pruned blocks",
		"start_height", 1,
		"end_height", halfPrune,
	)
	for h := 1; h <= halfPrune; h++ {
		if _, err := ctrl.Consensus.GetBlock(ctx, int64(h)); err == nil { // if NO error
			return fmt.Errorf("unexpected block (height: %d)", h)
		}
	}

	return sc.Net.CheckLogWatchers()
}
