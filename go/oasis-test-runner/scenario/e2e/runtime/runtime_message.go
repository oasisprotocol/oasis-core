package runtime

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// RuntimeMessage is the runtime message scenario.
var RuntimeMessage scenario.Scenario = newRuntimeMessage()

type runtimeMessageImpl struct {
	Scenario
}

func newRuntimeMessage() scenario.Scenario {
	return &runtimeMessageImpl{
		Scenario: *NewScenario("runtime-message", nil),
	}
}

func (sc *runtimeMessageImpl) Clone() scenario.Scenario {
	return &runtimeMessageImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *runtimeMessageImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}
	// Use mock epoch to ensure no rounds due to epoch transition. This way we
	// test batch proposals when there are no transactions but message results.
	f.Network.SetMockEpoch()
	return f, nil
}

func (sc *runtimeMessageImpl) Run(ctx context.Context, _ *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	var epoch beacon.EpochTime
	if epoch, err = sc.initialEpochTransitions(ctx, fixture); err != nil {
		return err
	}

	c := sc.Net.ClientController().RuntimeClient

	blkCh, sub, err := c.WatchBlocks(ctx, KeyValueRuntimeID)
	if err != nil {
		return err
	}
	defer sub.Close()

	// Submit a consensus transfer transaction. This should result in two runtime
	// rounds:
	//   - in first round the consensus transfer transaction should be executed
	//   - in the second round there should be no transactions, the round should
	//     contain message results of the consensus transfer.
	sc.Logger.Debug("submitting consensus_transfer runtime transaction")
	var txMetaResponse *api.SubmitTxMetaResponse
	if txMetaResponse, err = sc.submitConsensusXferTxMeta(ctx, staking.Transfer{}, 0); err != nil {
		return err
	}
	if _, err = unpackRawTxResp(txMetaResponse.Output); err != nil {
		return err
	}

	sc.Logger.Debug("transaction successful",
		"epoch", epoch,
		"round", txMetaResponse.Round,
	)
	latestRound := txMetaResponse.Round

	// Round with the submitted consensus_transfer transaction.
	blk, err := sc.WaitRuntimeBlock(blkCh, latestRound)
	if err != nil {
		return err
	}
	if ht := blk.Block.Header.HeaderType; ht != block.Normal {
		return fmt.Errorf("expected normal round, got: %d", ht)
	}

	txs, err := c.GetTransactions(ctx, &api.GetTransactionsRequest{
		RuntimeID: blk.Block.Header.Namespace,
		Round:     blk.Block.Header.Round,
	})
	if err != nil {
		return err
	}

	if len(txs) != 1 {
		return fmt.Errorf("expected 1 transaction at round: %d, got: %d", blk.Block.Header.Round, len(txs))
	}

	// Round with no transactions - triggered due to message results.
	blk, err = sc.WaitRuntimeBlock(blkCh, blk.Block.Header.Round+1)
	if err != nil {
		return err
	}
	if ht := blk.Block.Header.HeaderType; ht != block.Normal {
		return fmt.Errorf("expected normal round, got: %d", ht)
	}

	txs, err = c.GetTransactions(ctx, &api.GetTransactionsRequest{
		RuntimeID: blk.Block.Header.Namespace,
		Round:     blk.Block.Header.Round,
	})
	if err != nil {
		return err
	}

	if len(txs) != 0 {
		return fmt.Errorf("expected 0 transactions at round: %d, got: %d", blk.Block.Header.Round, len(txs))
	}

	return nil
}
