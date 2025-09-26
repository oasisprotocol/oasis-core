package runtime

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
)

// RuntimeTxs tests whether multiple transactions from the same sender
// can be included in a single block.
var RuntimeTxs scenario.Scenario = newRuntimeTxsImpl()

type runtimeTxsImpl struct {
	Scenario
}

func newRuntimeTxsImpl() scenario.Scenario {
	return &runtimeTxsImpl{
		Scenario: *NewScenario("runtime-txs", nil),
	}
}

func (sc *runtimeTxsImpl) Clone() scenario.Scenario {
	return &runtimeTxsImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *runtimeTxsImpl) Fixture() (*oasis.NetworkFixture, error) {
	return sc.Scenario.Fixture()
}

func (sc *runtimeTxsImpl) Run(ctx context.Context, _ *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	if err := sc.Net.ClientController().WaitReady(ctx); err != nil {
		return err
	}

	// Queue transactions with higher nonces which should not be included
	// in a block until transactions with lower nonces are submitted.
	group, gctx := errgroup.WithContext(ctx)

	batch := map[string][]uint64{
		"sender-1": {1},
		"sender-2": {1, 2},
		"sender-3": {1, 2, 3},
	}
	sc.submitTxs(gctx, group, batch)

	// Wait a bit to be sure that transactions are waiting in the pool
	// and are not included in a block.
	time.Sleep(10 * time.Second)

	// Queue missing transactions.
	batch = map[string][]uint64{
		"sender-0": {0},
		"sender-1": {0},
		"sender-2": {0},
		"sender-3": {0},
	}
	sc.submitTxs(gctx, group, batch)

	// Wait for transactions to be included in a block.
	if err := group.Wait(); err != nil {
		return err
	}

	// Verify that all transactions were included in a block.
	txs, err := sc.Net.ClientController().RuntimeClient.GetTransactions(ctx, &api.GetTransactionsRequest{
		RuntimeID: KeyValueRuntimeID,
		Round:     api.RoundLatest,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch latest transactions: %w", err)
	}

	if len(txs) != 10 {
		return fmt.Errorf("invalid number of transactions: %d", len(txs))
	}

	// Verify state.
	expectedValues := map[string]string{
		"sender-0": "0",
		"sender-1": "1",
		"sender-2": "2",
		"sender-3": "3",
	}

	for sender, expected := range expectedValues {
		value, err := sc.submitKeyValueRuntimeGetQuery(ctx, KeyValueRuntimeID, sender, api.RoundLatest)
		if err != nil {
			return fmt.Errorf("failed to query key %s: %w", sender, err)
		}
		if value != expected {
			return fmt.Errorf("unexpected value for key %s: got %s, want %s", sender, value, expected)
		}
	}

	return nil
}

func (sc *runtimeTxsImpl) submitTxs(ctx context.Context, group *errgroup.Group, batch map[string][]uint64) {
	for sender, nonces := range batch {
		for _, nonce := range nonces {
			group.Go(func() error {
				return sc.submitTx(ctx, sender, nonce)
			})
		}
	}
}

func (sc *runtimeTxsImpl) submitTx(ctx context.Context, sender string, nonce uint64) error {
	key := sender
	value := fmt.Sprintf("%d", nonce)
	_, err := sc.submitKeyValueRuntimeInsertTx(ctx, KeyValueRuntimeID, sender, nonce, key, value, 0, 0, plaintextTxKind)
	return err
}
