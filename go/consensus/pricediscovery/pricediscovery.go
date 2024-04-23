// Package pricediscovery implements gas price discovery.
package pricediscovery

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

const (
	// defaultWindowSize is the default number of recent blocks to use for calculating min gas
	// price.
	//
	// NOTE: Code assumes that this is relatively small.
	windowSize int = 6
)

type priceDiscovery struct {
	mu sync.RWMutex

	// finalGasPrice is protected by the mutex.
	finalGasPrice *quantity.Quantity

	fallbackGasPrice *quantity.Quantity
	minGasPrice      *quantity.Quantity
	computedGasPrice *quantity.Quantity
	// blockPrices is a rolling-array containing minimum transaction prices for last up to
	// `windowSize` blocks.
	blockPrices []*quantity.Quantity
	// tracks the current index of the blockPrices rolling array.
	blockPricesCurrentIdx int

	client consensus.ClientBackend

	logger *logging.Logger
}

// GasPrice implements consensus.PriceDiscovery.
func (pd *priceDiscovery) GasPrice() (*quantity.Quantity, error) {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	return pd.finalGasPrice, nil
}

// refreshMinGasPrice refreshes minimum gas price reported by the consensus layer.
func (pd *priceDiscovery) refreshMinGasPrice(ctx context.Context) {
	mgp, err := pd.client.MinGasPrice(ctx)
	if err != nil {
		pd.logger.Warn("failed to fetch minimum gas price",
			"err", err,
		)
		return
	}

	pd.minGasPrice = mgp
}

// processBlock computes the gas price based on transactions in a block.
func (pd *priceDiscovery) processBlock(_ context.Context, _ *consensus.Block) {
	// Currently transactions are not ordered by price, so track price as zero. After the mempool
	// is refactored, change this to properly compute the median gas price. Note that simply sorting
	// transactions here wouldn't work as it wouldn't reflect the actual queuing process until the
	// mempool is updated.
	//
	// We should also make sure to add some margin over the median in case of full blocks.
	pd.trackPrice(quantity.NewQuantity())
}

// trackPrice records the price for a block.
func (pd *priceDiscovery) trackPrice(price *quantity.Quantity) {
	pd.blockPrices[pd.blockPricesCurrentIdx] = price
	pd.blockPricesCurrentIdx = (pd.blockPricesCurrentIdx + 1) % windowSize

	// Find maximum gas price.
	maxPrice := quantity.NewFromUint64(0)
	for _, price := range pd.blockPrices {
		if price.Cmp(maxPrice) > 0 {
			maxPrice = price
		}
	}

	// No full blocks among last `windowSize` blocks.
	if maxPrice.IsZero() {
		maxPrice = nil
	}
	pd.computedGasPrice = maxPrice
}

func (pd *priceDiscovery) worker(ctx context.Context, ch <-chan *consensus.Block, sub pubsub.ClosableSubscription) {
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case blk := <-ch:
			pd.refreshMinGasPrice(ctx)
			pd.processBlock(ctx, blk)

			// Choose the maximum of (fallback, min, computed) gas prices.
			gasPrice := pd.fallbackGasPrice
			if pd.computedGasPrice != nil && pd.computedGasPrice.Cmp(gasPrice) > 0 {
				gasPrice = pd.computedGasPrice
			}
			if pd.minGasPrice.Cmp(gasPrice) > 0 {
				gasPrice = pd.minGasPrice
			}

			pd.mu.Lock()
			pd.finalGasPrice = gasPrice.Clone()
			pd.mu.Unlock()
		}
	}
}

// New creates a new dynamic price discovery implementation.
func New(ctx context.Context, client consensus.ClientBackend, fallbackGasPrice uint64) (consensus.PriceDiscovery, error) {
	pd := &priceDiscovery{
		fallbackGasPrice: quantity.NewFromUint64(fallbackGasPrice),
		minGasPrice:      quantity.NewQuantity(),
		computedGasPrice: quantity.NewQuantity(),
		client:           client,
		logger:           logging.GetLogger("consensus/pricediscovery"),
	}

	pd.blockPrices = make([]*quantity.Quantity, windowSize)
	for i := range windowSize {
		pd.blockPrices[i] = quantity.NewQuantity()
	}

	// Subscribe to consensus layer blocks and start watching.
	ch, sub, err := pd.client.WatchBlocks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to block updates: %w", err)
	}
	go pd.worker(ctx, ch, sub)

	return pd, nil
}
