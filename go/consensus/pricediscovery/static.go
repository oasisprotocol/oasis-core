package pricediscovery

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

type staticPriceDiscovery struct {
	price quantity.Quantity
}

// NewStatic creates a price discovery mechanism which always returns the same static price
// specified at construction time.
func NewStatic(price uint64) (consensus.PriceDiscovery, error) {
	pd := &staticPriceDiscovery{}
	if err := pd.price.FromUint64(price); err != nil {
		return nil, fmt.Errorf("submission: failed to convert gas price: %w", err)
	}
	return pd, nil
}

func (pd *staticPriceDiscovery) GasPrice() (*quantity.Quantity, error) {
	return pd.price.Clone(), nil
}
