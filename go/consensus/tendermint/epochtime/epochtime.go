// Package epochtime implements the tendermint backed epochtime backend.
package epochtime

import (
	"context"
	"fmt"
	"sync"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	"github.com/oasisprotocol/oasis-core/go/epochtime/api"
)

// ServiceClient is the beacon service client interface.
type ServiceClient interface {
	api.Backend
	tmapi.ServiceClient
}

type serviceClient struct {
	tmapi.BaseServiceClient
	sync.RWMutex

	logger *logging.Logger

	notifier *pubsub.Broker

	interval     int64
	lastNotified api.EpochTime
	epoch        api.EpochTime
	base         api.EpochTime
}

func (sc *serviceClient) GetBaseEpoch(context.Context) (api.EpochTime, error) {
	return sc.base, nil
}

func (sc *serviceClient) GetEpoch(ctx context.Context, height int64) (api.EpochTime, error) {
	if height == 0 {
		sc.RLock()
		defer sc.RUnlock()
		return sc.epoch, nil
	}
	epoch := sc.base + api.EpochTime(height/sc.interval)

	return epoch, nil
}

func (sc *serviceClient) GetEpochBlock(ctx context.Context, epoch api.EpochTime) (int64, error) {
	if epoch < sc.base {
		return 0, fmt.Errorf("epochtime/tendermint: epoch predates base")
	}
	height := int64(epoch-sc.base) * sc.interval

	return height, nil
}

func (sc *serviceClient) WatchEpochs() (<-chan api.EpochTime, *pubsub.Subscription) {
	typedCh := make(chan api.EpochTime)
	sub := sc.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (sc *serviceClient) WatchLatestEpoch() (<-chan api.EpochTime, *pubsub.Subscription) {
	typedCh := make(chan api.EpochTime)
	sub := sc.notifier.SubscribeBuffered(1)
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (sc *serviceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	return &api.Genesis{
		Parameters: api.ConsensusParameters{
			DebugMockBackend: false,
			Interval:         sc.interval,
		},
		// No need to set base epoch as we support restoring from a non-zero height.
		Base: 0,
	}, nil
}

func (sc *serviceClient) ConsensusParameters(ctx context.Context, height int64) (*api.ConsensusParameters, error) {
	return &api.ConsensusParameters{
		DebugMockBackend: false,
		Interval:         sc.interval,
	}, nil
}

// Implements api.ServiceClient.
func (sc *serviceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, "", nil)
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverBlock(ctx context.Context, height int64) error {
	epoch, _ := sc.GetEpoch(ctx, height)

	sc.Lock()
	defer sc.Unlock()

	sc.epoch = epoch

	if sc.lastNotified != epoch {
		sc.logger.Debug("epoch transition",
			"prev_epoch", sc.lastNotified,
			"epoch", epoch,
		)
		sc.lastNotified = epoch
		sc.notifier.Broadcast(epoch)
	}
	return nil
}

// New constructs a new tendermint backed epochtime Backend instance,
// with the specified epoch interval.
func New(ctx context.Context, backend tmapi.Backend, interval int64) (ServiceClient, error) {
	genDoc, err := backend.GetGenesisDocument(ctx)
	if err != nil {
		return nil, err
	}

	base := genDoc.EpochTime.Base
	sc := &serviceClient{
		logger:   logging.GetLogger("epochtime/tendermint"),
		interval: interval,
		base:     base,
		epoch:    base,
	}
	sc.notifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
		sc.RLock()
		defer sc.RUnlock()

		if sc.lastNotified == sc.epoch {
			ch.In() <- sc.epoch
		}
	})

	return sc, nil
}
