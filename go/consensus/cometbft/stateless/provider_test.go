package stateless

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

func TestCompositeProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("EstimateGas", func(t *testing.T) {
		p0 := newMockBackend(0, false)
		p1 := newMockBackend(1, false)
		p2 := newMockBackend(2, true)

		providers := []consensusAPI.Backend{p0, p1, p2}
		provider := NewCompositeProvider(providers)

		// The first call selects a provider at random.
		gas, err := provider.EstimateGas(ctx, nil)
		require.NoError(t, err)
		require.Contains(t, []transaction.Gas{p0.gas, p1.gas}, gas)

		// Subsequent calls should use the same provider.
		for range 5 {
			gas2, err := provider.EstimateGas(ctx, nil)
			require.NoError(t, err)
			require.Equal(t, gas, gas2)
		}

		// Disable the current providers.
		p0.disable()
		p1.disable()
		p2.enable()

		// The next call should switch to an available provider.
		gas, err = provider.EstimateGas(ctx, nil)
		require.NoError(t, err)
		require.Equal(t, p2.gas, gas)

		// Disable all providers.
		p2.disable()

		// The next call should fail due to no available providers.
		_, err = provider.EstimateGas(ctx, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to estimate gas from any provider")

		// Re-enable one provider.
		p1.enable()

		// The next call should succeed using the re-enabled provider.
		gas, err = provider.EstimateGas(ctx, nil)
		require.NoError(t, err)
		require.Equal(t, p1.gas, gas)
	})

	t.Run("WatchBlocks", func(t *testing.T) {
		p0 := newMockBackend(0, false)
		p1 := newMockBackend(0, true)

		providers := []consensusAPI.Backend{p0, p1}
		provider := NewCompositeProvider(providers)

		// The first call should select the first available provider.
		ch, sub, err := provider.WatchBlocks(ctx)
		require.NoError(t, err)
		defer sub.Close()

		// No blocks should be available immediately after startup.
		select {
		case <-ch:
			require.Fail(t, "unexpected block")
		case <-time.After(time.Millisecond):
		}

		// Send a few blocks through the currently selected provider.
		var height int64

		for range 5 {
			select {
			case p0.ch <- &consensusAPI.Block{Height: height}:
			default:
				require.Fail(t, "failed to send block to provider")
			}

			select {
			case blk := <-ch:
				require.Equal(t, height, blk.Height)
			case <-time.After(time.Millisecond):
				require.Fail(t, "expected to receive a block")
			}

			height++
		}

		// Simulate disconnection.
		p0.disable()

		// Re-enable provider.
		p0.enable()

		// Continue sending blocks to the re-enabled provider.
		for range 5 {
			select {
			case p0.ch <- &consensusAPI.Block{Height: height}:
			default:
				require.Fail(t, "failed to send block to provider")
			}

			select {
			case blk := <-ch:
				require.Equal(t, height, blk.Height)
			case <-time.After(time.Millisecond):
				require.Fail(t, "expected to receive a block")
			}

			height++
		}

		// Enable the second provider.
		p1.enable()

		// Disable the first provider.
		p0.disable()

		// Send blocks with lower height — they should be ignored.
		for i := range 5 {
			select {
			case p1.ch <- &consensusAPI.Block{Height: height - 5 + int64(i)}:
			default:
				require.Fail(t, "failed to send block to provider")
			}

			select {
			case <-ch:
				require.Fail(t, "unexpected block")
			case <-time.After(time.Millisecond):
			}
		}

		// Send valid blocks — they should be accepted.
		for range 5 {
			select {
			case p1.ch <- &consensusAPI.Block{Height: height}:
			default:
				require.Fail(t, "failed to send block to provider")
			}

			select {
			case blk := <-ch:
				require.Equal(t, height, blk.Height)
			case <-time.After(time.Millisecond):
				require.Fail(t, "expected to receive a block")
			}

			height++
		}

		// Simulate skipped blocks by sending a block with a height gap.
		select {
		case p1.ch <- &consensusAPI.Block{Height: height + 4}:
		default:
			require.Fail(t, "failed to send block to provider")
		}

		// All missing blocks should be fetched manually.
		for range 5 {
			select {
			case blk := <-ch:
				require.Equal(t, height, blk.Height)
			case <-time.After(time.Millisecond):
				require.Fail(t, "expected to receive a block")
			}

			height++
		}
	})
}

func TestProviderScorer(t *testing.T) {
	p0 := newMockBackend(0, false)
	p1 := newMockBackend(0, false)
	p2 := newMockBackend(0, false)

	providers := []consensusAPI.Backend{p0, p1, p2}
	scorer := newProviderScorer(providers)

	// Initially all scores should be 0.
	require.Equal(t, 0, scorer.score(p0))
	require.Equal(t, 0, scorer.score(p1))
	require.Equal(t, 0, scorer.score(p2))

	// Boost scores.
	scorer.boostScore(p0)
	scorer.boostScore(p1)
	scorer.boostScore(p1)
	scorer.boostScore(p1)
	scorer.boostScore(p2)
	scorer.boostScore(p2)

	// Verify scores.
	require.Equal(t, 1, scorer.score(p0))
	require.Equal(t, 3, scorer.score(p1))
	require.Equal(t, 2, scorer.score(p2))

	// Check ordering.
	top := slices.Collect(scorer.topProviders())
	expected := []consensusAPI.Backend{p1, p2, p0}
	require.Equal(t, expected, top)

	// Reset one score.
	scorer.resetScore(p1)

	// Verify scores.
	require.Equal(t, 1, scorer.score(p0))
	require.Equal(t, 0, scorer.score(p1))
	require.Equal(t, 2, scorer.score(p2))

	// Check ordering.
	top = slices.Collect(scorer.topProviders())
	expected = []consensusAPI.Backend{p2, p0, p1}
	require.Equal(t, expected, top)
}

type mockBackend struct {
	mu       sync.Mutex
	disabled bool
	gas      transaction.Gas
	ch       chan *consensusAPI.Block
}

func newMockBackend(gas transaction.Gas, disabled bool) *mockBackend {
	return &mockBackend{
		disabled: disabled,
		gas:      gas,
		ch:       make(chan *consensusAPI.Block, 1),
	}
}

func (b *mockBackend) enable() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.disabled = false
	b.ch = make(chan *consensusAPI.Block, 1)
}

func (b *mockBackend) disable() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.disabled = true
	close(b.ch)
}

// EstimateGas implements api.Backend.
func (b *mockBackend) EstimateGas(context.Context, *consensusAPI.EstimateGasRequest) (transaction.Gas, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.disabled {
		return 0, fmt.Errorf("backend disabled")
	}

	return b.gas, nil
}

// GetBlock implements api.Backend.
func (b *mockBackend) GetBlock(_ context.Context, height int64) (*consensusAPI.Block, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.disabled {
		return nil, fmt.Errorf("backend disabled")
	}

	return &consensusAPI.Block{Height: height}, nil
}

// GetBlockResults implements api.Backend.
func (b *mockBackend) GetBlockResults(context.Context, int64) (*consensusAPI.BlockResults, error) {
	panic("unimplemented")
}

// GetChainContext implements api.Backend.
func (b *mockBackend) GetChainContext(context.Context) (string, error) {
	panic("unimplemented")
}

// GetGenesisDocument implements api.Backend.
func (b *mockBackend) GetGenesisDocument(context.Context) (*api.Document, error) {
	panic("unimplemented")
}

// GetLastRetainedHeight implements api.Backend.
func (b *mockBackend) GetLastRetainedHeight(context.Context) (int64, error) {
	panic("unimplemented")
}

// GetLatestHeight implements api.Backend.
func (b *mockBackend) GetLatestHeight(context.Context) (int64, error) {
	panic("unimplemented")
}

// GetLightBlock implements api.Backend.
func (b *mockBackend) GetLightBlock(context.Context, int64) (*consensusAPI.LightBlock, error) {
	panic("unimplemented")
}

// GetValidators implements api.Backend.
func (b *mockBackend) GetValidators(context.Context, int64) (*consensusAPI.Validators, error) {
	panic("unimplemented")
}

// GetNextBlockState implements api.Backend.
func (b *mockBackend) GetNextBlockState(context.Context) (*consensusAPI.NextBlockState, error) {
	panic("unimplemented")
}

// GetParameters implements api.Backend.
func (b *mockBackend) GetParameters(context.Context, int64) (*consensusAPI.Parameters, error) {
	panic("unimplemented")
}

// GetSignerNonce implements api.Backend.
func (b *mockBackend) GetSignerNonce(context.Context, *consensusAPI.GetSignerNonceRequest) (uint64, error) {
	panic("unimplemented")
}

// GetStatus implements api.Backend.
func (b *mockBackend) GetStatus(context.Context) (*consensusAPI.Status, error) {
	panic("unimplemented")
}

// GetTransactions implements api.Backend.
func (b *mockBackend) GetTransactions(context.Context, int64) ([][]byte, error) {
	panic("unimplemented")
}

// GetTransactionsWithProofs implements api.Backend.
func (b *mockBackend) GetTransactionsWithProofs(context.Context, int64) (*consensusAPI.TransactionsWithProofs, error) {
	panic("unimplemented")
}

// GetTransactionsWithResults implements api.Backend.
func (b *mockBackend) GetTransactionsWithResults(context.Context, int64) (*consensusAPI.TransactionsWithResults, error) {
	panic("unimplemented")
}

// GetUnconfirmedTransactions implements api.Backend.
func (b *mockBackend) GetUnconfirmedTransactions(context.Context) ([][]byte, error) {
	panic("unimplemented")
}

// MinGasPrice implements api.Backend.
func (b *mockBackend) MinGasPrice(context.Context) (*quantity.Quantity, error) {
	panic("unimplemented")
}

// State implements api.Backend.
func (b *mockBackend) State() syncer.ReadSyncer {
	panic("unimplemented")
}

// StateToGenesis implements api.Backend.
func (b *mockBackend) StateToGenesis(context.Context, int64) (*api.Document, error) {
	panic("unimplemented")
}

// SubmitEvidence implements api.Backend.
func (b *mockBackend) SubmitEvidence(context.Context, *consensusAPI.Evidence) error {
	panic("unimplemented")
}

// SubmitTx implements api.Backend.
func (b *mockBackend) SubmitTx(context.Context, *transaction.SignedTransaction) error {
	panic("unimplemented")
}

// SubmitTxNoWait implements api.Backend.
func (b *mockBackend) SubmitTxNoWait(context.Context, *transaction.SignedTransaction) error {
	panic("unimplemented")
}

// SubmitTxWithProof implements api.Backend.
func (b *mockBackend) SubmitTxWithProof(context.Context, *transaction.SignedTransaction) (*transaction.Proof, error) {
	panic("unimplemented")
}

// WatchBlocks implements api.Backend.
func (b *mockBackend) WatchBlocks(ctx context.Context) (<-chan *consensusAPI.Block, pubsub.ClosableSubscription, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.disabled {
		return nil, nil, fmt.Errorf("backend disabled")
	}

	_, sub := pubsub.NewContextSubscription(ctx)
	return b.ch, sub, nil
}
