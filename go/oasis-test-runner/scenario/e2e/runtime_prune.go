package e2e

import (
	"context"
	"fmt"
	"time"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasislabs/oasis-core/go/runtime/client/api"
	"github.com/oasislabs/oasis-core/go/runtime/history"
)

var (
	// RuntimePrune is the runtime prune scenario.
	RuntimePrune scenario.Scenario = newRuntimePruneImpl()
)

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
	basicImpl

	logger *logging.Logger
}

func newRuntimePruneImpl() scenario.Scenario {
	sc := &runtimePruneImpl{
		basicImpl: basicImpl{
			clientBinary: "", // We use a Go client.
		},
		logger: logging.GetLogger("scenario/e2e/runtime_prune"),
	}
	return sc
}

func (sc *runtimePruneImpl) Name() string {
	return "runtime-prune"
}

func (sc *runtimePruneImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Avoid unexpected blocks.
	f.Network.EpochtimeMock = true
	// Configure pruning.
	f.Runtimes[1].Pruner = oasis.RuntimePrunerCfg{
		Strategy: history.PrunerStrategyKeepLast,
		Interval: pruneInterval,
		NumKept:  pruneNumKept,
	}

	return f, nil
}

func (sc *runtimePruneImpl) Run(childEnv *env.Env) error {
	if err := sc.net.Start(); err != nil {
		return err
	}

	ctx := context.Background()

	sc.logger.Info("waiting for nodes to register",
		"num_nodes", sc.net.NumRegisterNodes(),
	)
	if err := sc.net.Controller().WaitNodesRegistered(ctx, sc.net.NumRegisterNodes()); err != nil {
		return err
	}

	sc.logger.Info("triggering epoch transition")
	if err := sc.net.Controller().SetEpoch(ctx, 1); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}
	sc.logger.Info("epoch transition done")

	c := sc.net.ClientController().RuntimeClient

	// Submit transactions.
	for i := 0; i < pruneTxCount; i++ {
		sc.logger.Info("submitting transaction to runtime",
			"seq", i,
		)

		if err := sc.submitRuntimeTx(ctx, "hello", fmt.Sprintf("world %d", i)); err != nil {
			return err
		}
	}

	// Wait long enough that something should be pruned.
	time.Sleep(pruneInterval + 1*time.Second)

	// Once the transactions are complete, check if blocks got pruned.
	sc.logger.Info("fetching latest block")
	latestBlk, err := c.GetBlock(ctx, &api.GetBlockRequest{
		RuntimeID: runtimeID,
		Round:     api.RoundLatest,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch latest block: %w", err)
	}

	sc.logger.Info("checking if blocks got pruned correctly",
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
