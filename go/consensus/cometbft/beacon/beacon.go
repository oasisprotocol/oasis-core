// Package beacon implements the CometBFT backed beacon and epochtime
// backends.
package beacon

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cache/lru"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	cmtapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon"
)

// epochCacheCapacity is the capacity of the epoch LRU cache.
const epochCacheCapacity = 128

// ServiceClient is the beacon service client.
type ServiceClient struct {
	sync.RWMutex
	cmtapi.BaseServiceClient

	logger *logging.Logger

	consensus  consensus.Backend
	querier    QueryFactory
	descriptor *cmtapi.ServiceDescriptor

	epochNotifier     *pubsub.Broker
	epochLastNotified api.EpochTime
	epoch             api.EpochTime
	epochCurrentBlock int64
	epochCache        *lru.Cache

	vrfNotifier     *pubsub.Broker
	vrfLastNotified hash.Hash
	vrfEvent        *api.VRFEvent

	initialNotify bool

	baseEpoch api.EpochTime
	baseBlock int64
}

// New constructs a new CometBFT backed beacon service client.
func New(baseEpoch api.EpochTime, baseBlock int64, consensus consensus.Backend, querier QueryFactory) *ServiceClient {
	descriptor := cmtapi.NewServiceDescriptor(api.ModuleName, app.EventType, 1)
	descriptor.AddQuery(app.QueryApp)

	return &ServiceClient{
		logger:            logging.GetLogger("cometbft/beacon"),
		consensus:         consensus,
		querier:           querier,
		descriptor:        descriptor,
		epochNotifier:     pubsub.NewBroker(false),
		epochLastNotified: api.EpochInvalid,
		epochCache:        lru.New(lru.Capacity(epochCacheCapacity, false)),
		vrfNotifier:       pubsub.NewBroker(false),
		baseEpoch:         baseEpoch,
		baseBlock:         baseBlock,
	}
}

func (sc *ServiceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (sc *ServiceClient) ConsensusParameters(ctx context.Context, height int64) (*api.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("beacon: genesis query failed: %w", err)
	}

	return q.ConsensusParameters(ctx)
}

func (sc *ServiceClient) GetBaseEpoch(context.Context) (api.EpochTime, error) {
	return sc.baseEpoch, nil
}

func (sc *ServiceClient) GetEpoch(ctx context.Context, height int64) (api.EpochTime, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return api.EpochInvalid, err
	}

	epoch, _, err := q.Epoch(ctx)
	return epoch, err
}

func (sc *ServiceClient) GetFutureEpoch(ctx context.Context, height int64) (*api.EpochTimeState, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.FutureEpoch(ctx)
}

func (sc *ServiceClient) GetEpochBlock(ctx context.Context, epoch api.EpochTime) (int64, error) {
	now, currentBlk := sc.currentEpochBlock()
	switch {
	case epoch == now:
		return currentBlk, nil
	case epoch < sc.baseEpoch:
		return 0, fmt.Errorf("epoch predates base (base: %d requested: %d)", sc.baseEpoch, epoch)
	case epoch == sc.baseEpoch:
		return sc.baseBlock, nil
	}

	// Try the cache first.
	if cachedHeight, ok := sc.epochCache.Get(epoch); ok {
		return cachedHeight.(int64), nil
	}

	lowHeight, err := sc.consensus.GetLastRetainedHeight(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to query last retained version: %w", err)
	}

	hiHeight, err := sc.consensus.GetLatestHeight(ctx)
	if err != nil {
		return 0, err
	}
	// Start with the latest height as it is possible that currentEpochBlock is not the most up to
	// date in cases where GetEpochBlock is called during epoch transitions.
	height := hiHeight

	// Find historic epoch with bounded bisection.
	const maxIterations = 20 // Should be good enough for most use cases.
	var prevEpoch api.EpochTime
	for range maxIterations {
		q, err := sc.querier.QueryAt(ctx, height)
		if err != nil {
			return 0, fmt.Errorf("failed to query epoch: %w", err)
		}

		var (
			curEpoch    api.EpochTime
			epochHeight int64
		)
		curEpoch, epochHeight, err = q.Epoch(ctx)
		if err != nil {
			return 0, fmt.Errorf("failed to query epoch: %w", err)
		}
		if curEpoch == prevEpoch {
			break
		}
		prevEpoch = curEpoch

		switch {
		case epoch == curEpoch:
			_ = sc.epochCache.Put(curEpoch, epochHeight)
			return epochHeight, nil
		case epoch < curEpoch:
			hiHeight = epochHeight
		case epoch > curEpoch:
			lowHeight = height
		}

		// Determine next height as the midpoint between the two.
		height = (lowHeight + hiHeight) / 2
	}
	return 0, fmt.Errorf("failed to find historic epoch")
}

func (sc *ServiceClient) WaitEpoch(ctx context.Context, epoch api.EpochTime) error {
	ch, sub, err := sc.WatchEpochs(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-ch:
			if !ok {
				return context.Canceled
			}
			if e >= epoch {
				return nil
			}
		}
	}
}

func (sc *ServiceClient) WatchEpochs(context.Context) (<-chan api.EpochTime, pubsub.ClosableSubscription, error) {
	hook := sc.epochNotifierHook()
	ch := make(chan api.EpochTime)
	sub := sc.epochNotifier.SubscribeEx(hook)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) WatchLatestEpoch(context.Context) (<-chan api.EpochTime, pubsub.ClosableSubscription, error) {
	hook := sc.epochNotifierHook()
	ch := make(chan api.EpochTime)
	sub := sc.epochNotifier.SubscribeBufferedEx(1, hook)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) GetBeacon(ctx context.Context, height int64) ([]byte, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Beacon(ctx)
}

func (sc *ServiceClient) GetVRFState(ctx context.Context, height int64) (*api.VRFState, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.VRFState(ctx)
}

func (sc *ServiceClient) WatchLatestVRFEvent(context.Context) (<-chan *api.VRFEvent, *pubsub.Subscription, error) {
	hook := sc.vrfNotifierHook()
	ch := make(chan *api.VRFEvent)
	sub := sc.vrfNotifier.SubscribeEx(hook)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) ServiceDescriptor() *cmtapi.ServiceDescriptor {
	return sc.descriptor
}

func (sc *ServiceClient) DeliverHeight(ctx context.Context, height int64) error {
	if sc.initialNotify {
		return nil
	}

	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return fmt.Errorf("epochtime: failed to query state: %w", err)
	}

	epoch, height, err := q.Epoch(ctx)
	if err != nil {
		return fmt.Errorf("epochtime: failed to query epoch: %w", err)
	}

	if sc.updateCachedEpoch(height, epoch) {
		sc.epochNotifier.Broadcast(epoch)
	}

	var vrfState *api.VRFState
	vrfState, err = q.VRFState(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to query VRF state: %w", err)
	}
	if vrfState != nil {
		var event api.VRFEvent
		event.FromState(vrfState)

		if sc.updateCachedVRFEvent(&event) {
			sc.vrfNotifier.Broadcast(&event)
		}
	}

	sc.initialNotify = true
	return nil
}

func (sc *ServiceClient) DeliverEvent(_ context.Context, height int64, ev *cmtabcitypes.Event) error {
	for _, pair := range ev.GetAttributes() {
		key := pair.GetKey()
		val := pair.GetValue()

		if events.IsAttributeKind(key, &api.EpochEvent{}) {
			var event api.EpochEvent
			if err := events.DecodeValue(val, &event); err != nil {
				sc.logger.Error("epochtime: malformed epoch event value",
					"err", err,
				)
				continue
			}

			if sc.updateCachedEpoch(height, event.Epoch) {
				sc.epochNotifier.Broadcast(event.Epoch)
			}
		}
		if events.IsAttributeKind(key, &api.VRFEvent{}) {
			var event api.VRFEvent
			if err := events.DecodeValue(val, &event); err != nil {
				sc.logger.Error("beacon: malformed VRF event",
					"err", err,
				)
				continue
			}
			if sc.updateCachedVRFEvent(&event) {
				sc.vrfNotifier.Broadcast(&event)
			}
		}
	}
	return nil
}

func (sc *ServiceClient) updateCachedEpoch(height int64, epoch api.EpochTime) bool {
	sc.Lock()
	defer sc.Unlock()

	sc.epoch = epoch
	sc.epochCurrentBlock = height
	_ = sc.epochCache.Put(epoch, height)

	if sc.epochLastNotified != epoch {
		sc.logger.Debug("epoch transition",
			"prev_epoch", sc.epochLastNotified,
			"epoch", epoch,
			"height", height,
		)
		sc.epochLastNotified = sc.epoch
		return true
	}
	return false
}

func (sc *ServiceClient) updateCachedVRFEvent(event *api.VRFEvent) bool {
	sc.Lock()
	defer sc.Unlock()

	sc.vrfEvent = event
	cmp := hash.NewFrom(event)

	if !cmp.Equal(&sc.vrfLastNotified) {
		sc.logger.Debug("VRF round event",
			"epoch", event.Epoch,
			"alpha", hex.EncodeToString(event.Alpha),
			"submit_after", event.SubmitAfter,
		)
		sc.vrfLastNotified = cmp
		return true
	}

	return false
}

func (sc *ServiceClient) currentEpochBlock() (api.EpochTime, int64) {
	sc.RLock()
	defer sc.RUnlock()

	return sc.epoch, sc.epochCurrentBlock
}

func (sc *ServiceClient) epochNotifierHook() pubsub.OnSubscribeHook {
	return func(ch channels.Channel) {
		sc.RLock()
		defer sc.RUnlock()

		if sc.epochLastNotified == sc.epoch {
			ch.In() <- sc.epoch
		}
	}
}

func (sc *ServiceClient) vrfNotifierHook() pubsub.OnSubscribeHook {
	return func(ch channels.Channel) {
		sc.RLock()
		defer sc.RUnlock()

		if sc.vrfEvent != nil {
			ch.In() <- sc.vrfEvent
		}
	}
}
