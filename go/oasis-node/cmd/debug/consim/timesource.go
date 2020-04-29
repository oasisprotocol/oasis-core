package consim

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/epochtime/api"
)

type simTimeSource struct {
	base     api.EpochTime
	current  api.EpochTime
	interval int64
}

func (b *simTimeSource) GetBaseEpoch(ctx context.Context) (api.EpochTime, error) {
	return b.base, nil
}

func (b *simTimeSource) GetEpoch(ctx context.Context, height int64) (api.EpochTime, error) {
	if height == 0 {
		return b.current, nil
	}
	return b.base + api.EpochTime(height/b.interval), nil
}

func (b *simTimeSource) GetEpochBlock(ctx context.Context, epoch api.EpochTime) (int64, error) {
	if epoch < b.base {
		return 0, fmt.Errorf("consim/epochtime: epoch predates base")
	}
	height := int64(epoch-b.base) * b.interval
	return height, nil
}

func (b *simTimeSource) WatchEpochs() (<-chan api.EpochTime, *pubsub.Subscription) {
	panic("consim/epochtime: WatchEpochs not supported")
}

func (b *simTimeSource) WatchLatestEpoch() (<-chan api.EpochTime, *pubsub.Subscription) {
	panic("consim/epochtime: WatchLatestEpoch not supported")
}

func (b *simTimeSource) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	// WARNING: This ignores the height because it's only used for the final
	// dump.
	return &api.Genesis{
		Base: b.current,
		Parameters: api.ConsensusParameters{
			Interval: b.interval,
		},
	}, nil
}

func newSimTimeSource(genesis *api.Genesis) *simTimeSource {
	return &simTimeSource{
		base:     genesis.Base,
		current:  genesis.Base,
		interval: genesis.Parameters.Interval,
	}
}
