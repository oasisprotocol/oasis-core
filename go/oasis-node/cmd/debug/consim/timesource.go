package consim

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
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

func (b *simTimeSource) GetFutureEpoch(ctx context.Context, height int64) (*api.EpochTimeState, error) {
	return nil, nil
}

func (b *simTimeSource) GetEpochBlock(ctx context.Context, epoch api.EpochTime) (int64, error) {
	if epoch < b.base {
		return 0, fmt.Errorf("consim/epochtime: epoch predates base")
	}
	height := int64(epoch-b.base) * b.interval
	return height, nil
}

func (b *simTimeSource) WaitEpoch(ctx context.Context, epoch api.EpochTime) error {
	panic("consim/epochtime: WaitEpoch not supported")
}

func (b *simTimeSource) WatchEpochs(ctx context.Context) (<-chan api.EpochTime, pubsub.ClosableSubscription, error) {
	panic("consim/epochtime: WatchEpochs not supported")
}

func (b *simTimeSource) WatchLatestEpoch(ctx context.Context) (<-chan api.EpochTime, pubsub.ClosableSubscription, error) {
	panic("consim/epochtime: WatchLatestEpoch not supported")
}

func (b *simTimeSource) GetBeacon(ctx context.Context, height int64) ([]byte, error) {
	panic("consim/epochtime: GetBeacon not supported")
}

func (b *simTimeSource) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	beaconParams, _ := b.ConsensusParameters(ctx, height)
	// WARNING: This ignores the height because it's only used for the final
	// dump.
	return &api.Genesis{
		Base:       b.current,
		Parameters: *beaconParams,
	}, nil
}

func (b *simTimeSource) ConsensusParameters(ctx context.Context, height int64) (*api.ConsensusParameters, error) {
	return &api.ConsensusParameters{
		Backend: api.BackendInsecure,
		InsecureParameters: &api.InsecureParameters{
			Interval: b.interval,
		},
	}, nil
}

func newSimTimeSource(genesis *api.Genesis) *simTimeSource {
	return &simTimeSource{
		base:     genesis.Base,
		current:  genesis.Base,
		interval: genesis.Parameters.InsecureParameters.Interval,
	}
}
