package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
)

// RuntimePrune is the runtime prune scenario.
var RuntimePrune scenario.Scenario = newRuntimePruneImpl()

const (
	// pruneNumKept is the number of last blocks the pruner should keep.
	pruneNumKept = 5
	// pruneTxCount is the number of txs that should be submitted (as we
	// are the only submitter, this is also the number of blocks).
	pruneTxCount = 10
	// pruneInterval is the prune interval.
	pruneInterval = 1 * time.Second
)

type runtimePruneImpl struct {
	runtimeImpl
}

func newRuntimePruneImpl() scenario.Scenario {
	return &runtimePruneImpl{
		runtimeImpl: *newRuntimeImpl("runtime-prune", nil),
	}
}

func (sc *runtimePruneImpl) Clone() scenario.Scenario {
	return &runtimePruneImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *runtimePruneImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Avoid unexpected blocks.
	f.Network.SetMockEpoch()
	// Configure pruning.
	f.Runtimes[1].Pruner = oasis.RuntimePrunerCfg{
		Strategy: history.PrunerStrategyKeepLast,
		Interval: pruneInterval,
		NumKept:  pruneNumKept,
	}

	return f, nil
}

func (sc *runtimePruneImpl) Run(childEnv *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	if _, err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}

	ctx := context.Background()
	c := sc.Net.ClientController().RuntimeClient

	// Submit transactions.
	for i := 0; i < pruneTxCount; i++ {
		sc.Logger.Info("submitting transaction to runtime",
			"seq", i,
		)

		if _, err = sc.submitKeyValueRuntimeInsertTx(ctx, runtimeID, "hello", fmt.Sprintf("world %d", i), uint64(i)); err != nil {
			return err
		}
	}

	// Wait long enough that something should be pruned.
	time.Sleep(pruneInterval + 1*time.Second)

	// Once the transactions are complete, check if blocks got pruned.
	sc.Logger.Info("fetching latest block")
	latestBlk, err := c.GetBlock(ctx, &api.GetBlockRequest{
		RuntimeID: runtimeID,
		Round:     api.RoundLatest,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch latest block: %w", err)
	}

	sc.Logger.Info("checking if blocks got pruned correctly",
		"latest_round", latestBlk.Header.Round,
	)
	for i := uint64(0); i <= latestBlk.Header.Round; i++ {
		_, err = c.GetBlock(ctx, &api.GetBlockRequest{
			RuntimeID: runtimeID,
			Round:     i,
		})
		if i <= latestBlk.Header.Round-pruneNumKept {
			// Block should be pruned.
			if err == nil {
				return fmt.Errorf("block %d should be pruned but is not", i)
			}
		} else {
			// Block should not be pruned.
			if err != nil {
				return fmt.Errorf("block %d is pruned but it shouldn't be", i)
			}
		}
	}

	return nil
}
