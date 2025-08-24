package runtime

import (
	"context"
	"fmt"

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

	// Submit multiple transactions concurrently from different users.
	type senderNonceTx struct {
		sender string
		nonce  uint64
	}

	submitTx := func(ctx context.Context, tx senderNonceTx) error {
		key := tx.sender
		value := fmt.Sprintf("%d", tx.nonce)
		_, err := sc.submitKeyValueRuntimeInsertTx(ctx, KeyValueRuntimeID, tx.sender, tx.nonce, key, value, 0, 0, plaintextTxKind)
		return err
	}
	submitTxs := func(ctx context.Context, txs []senderNonceTx, group *errgroup.Group) {
		for _, tx := range txs {
			group.Go(func() error {
				return submitTx(ctx, tx)
			})
		}
	}

	group1, ctx1 := errgroup.WithContext(ctx)
	group2, ctx2 := errgroup.WithContext(ctx)

	txs1 := []senderNonceTx{
		{"sender-1", 1},
		{"sender-2", 1},
		{"sender-2", 2},
		{"sender-3", 1},
		{"sender-3", 2},
		{"sender-3", 3},
	}
	txs2 := []senderNonceTx{
		{"sender-2", 4},
		{"sender-3", 5},
		{"sender-3", 6},
	}

	submitTxs(ctx1, txs1, group1)
	submitTxs(ctx2, txs2, group2)

	// Wait for the first block.
	if err := group1.Wait(); err != nil {
		return err
	}

	// Verify that all transactions from the first group are included in the first block.
	txs, err := sc.Net.ClientController().RuntimeClient.GetTransactions(ctx, &api.GetTransactionsRequest{
		RuntimeID: KeyValueRuntimeID,
		Round:     api.RoundLatest,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch latest transactions: %w", err)
	}

	if len(txs) != len(txs1) {
		return fmt.Errorf("invalid number of transactions")
	}

	// Verify the state after the first block.
	expectedValues := map[string]string{
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

	// Wait for the second block.
	if err := group2.Wait(); err != nil {
		return err
	}

	// Verify that all transactions from the second group are included in the second block.
	txs, err = sc.Net.ClientController().RuntimeClient.GetTransactions(ctx, &api.GetTransactionsRequest{
		RuntimeID: KeyValueRuntimeID,
		Round:     api.RoundLatest,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch latest transactions: %w", err)
	}

	if len(txs) != len(txs2) {
		return fmt.Errorf("invalid number of transactions")
	}

	// Verify the state after the second block.
	expectedValues = map[string]string{
		"sender-1": "1",
		"sender-2": "4",
		"sender-3": "6",
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
