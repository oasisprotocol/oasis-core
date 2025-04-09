// Package beacon implements the CometBFT backed beacon and epochtime
// backends.
package beacon

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/eapache/channels"

	beaconAPI "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cache/lru"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	tmAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon"
)

var TestSigner = memorySigner.NewTestSigner("oasis-core epochtime mock key seed")

// epochCacheCapacity is the capacity of the epoch LRU cache.
const epochCacheCapacity = 128

// ServiceClient is the beacon service client.
type ServiceClient struct {
	sync.RWMutex
	tmAPI.BaseServiceClient

	logger  *logging.Logger
	querier *app.QueryFactory

	backend tmAPI.Backend
	ctx     context.Context

	epochNotifier     *pubsub.Broker
	epochLastNotified beaconAPI.EpochTime
	epoch             beaconAPI.EpochTime
	epochCurrentBlock int64
	epochCache        *lru.Cache

	vrfNotifier     *pubsub.Broker
	vrfLastNotified hash.Hash
	vrfEvent        *beaconAPI.VRFEvent

	initialNotify bool

	baseEpoch beaconAPI.EpochTime
	baseBlock int64
}

func (sc *ServiceClient) StateToGenesis(ctx context.Context, height int64) (*beaconAPI.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (sc *ServiceClient) ConsensusParameters(ctx context.Context, height int64) (*beaconAPI.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("beacon: genesis query failed: %w", err)
	}

	return q.ConsensusParameters(ctx)
}

func (sc *ServiceClient) GetBaseEpoch(context.Context) (beaconAPI.EpochTime, error) {
	return sc.baseEpoch, nil
}

func (sc *ServiceClient) GetEpoch(ctx context.Context, height int64) (beaconAPI.EpochTime, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return beaconAPI.EpochInvalid, err
	}

	epoch, _, err := q.Epoch(ctx)
	return epoch, err
}

func (sc *ServiceClient) GetFutureEpoch(ctx context.Context, height int64) (*beaconAPI.EpochTimeState, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.FutureEpoch(ctx)
}

func (sc *ServiceClient) GetEpochBlock(ctx context.Context, epoch beaconAPI.EpochTime) (int64, error) {
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

	lowHeight, err := sc.backend.GetLastRetainedHeight(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to query last retained version: %w", err)
	}

	hiHeight, err := sc.backend.GetLatestHeight(ctx)
	if err != nil {
		return 0, err
	}
	// Start with the latest height as it is possible that currentEpochBlock is not the most up to
	// date in cases where GetEpochBlock is called during epoch transitions.
	height := hiHeight

	// Find historic epoch with bounded bisection.
	const maxIterations = 20 // Should be good enough for most use cases.
	var prevEpoch beaconAPI.EpochTime
	for range maxIterations {
		q, err := sc.querier.QueryAt(ctx, height)
		if err != nil {
			return 0, fmt.Errorf("failed to query epoch: %w", err)
		}

		var (
			curEpoch    beaconAPI.EpochTime
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

func (sc *ServiceClient) WaitEpoch(ctx context.Context, epoch beaconAPI.EpochTime) error {
	ch, sub, err := sc.WatchEpochs(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case <-sc.ctx.Done():
			return sc.ctx.Err()
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

func (sc *ServiceClient) WatchEpochs(_ context.Context) (<-chan beaconAPI.EpochTime, pubsub.ClosableSubscription, error) {
	typedCh := make(chan beaconAPI.EpochTime)
	sub := sc.epochNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *ServiceClient) WatchLatestEpoch(context.Context) (<-chan beaconAPI.EpochTime, pubsub.ClosableSubscription, error) {
	typedCh := make(chan beaconAPI.EpochTime)
	sub := sc.epochNotifier.SubscribeBuffered(1)
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *ServiceClient) GetBeacon(ctx context.Context, height int64) ([]byte, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Beacon(ctx)
}

func (sc *ServiceClient) GetVRFState(ctx context.Context, height int64) (*beaconAPI.VRFState, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.VRFState(ctx)
}

func (sc *ServiceClient) WatchLatestVRFEvent(context.Context) (<-chan *beaconAPI.VRFEvent, *pubsub.Subscription, error) {
	typedCh := make(chan *beaconAPI.VRFEvent)
	sub := sc.vrfNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *ServiceClient) SetEpoch(ctx context.Context, epoch beaconAPI.EpochTime) error {
	ch, sub, err := sc.WatchEpochs(ctx)
	if err != nil {
		return fmt.Errorf("epochtime: watch epochs failed: %w", err)
	}
	defer sub.Close()

	tx := transaction.NewTransaction(0, nil, app.MethodSetEpoch, epoch)
	if err := consensus.SignAndSubmitTx(ctx, sc.backend, TestSigner, tx); err != nil {
		return fmt.Errorf("epochtime: set epoch failed: %w", err)
	}

	for {
		select {
		case <-sc.ctx.Done():
			return sc.ctx.Err()
		case newEpoch, ok := <-ch:
			if !ok {
				return context.Canceled
			}
			if newEpoch == epoch {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (sc *ServiceClient) ServiceDescriptor() tmAPI.ServiceDescriptor {
	return tmAPI.NewStaticServiceDescriptor("beacon", app.EventType, []cmtpubsub.Query{app.QueryApp})
}

func (sc *ServiceClient) DeliverBlock(ctx context.Context, blk *cmttypes.Block) error {
	if sc.initialNotify {
		return nil
	}

	q, err := sc.querier.QueryAt(ctx, blk.Height)
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

	var vrfState *beaconAPI.VRFState
	vrfState, err = q.VRFState(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to query VRF state: %w", err)
	}
	if vrfState != nil {
		var event beaconAPI.VRFEvent
		event.FromState(vrfState)

		if sc.updateCachedVRFEvent(&event) {
			sc.vrfNotifier.Broadcast(&event)
		}
	}

	sc.initialNotify = true
	return nil
}

func (sc *ServiceClient) DeliverEvent(_ context.Context, height int64, _ cmttypes.Tx, ev *cmtabcitypes.Event) error {
	for _, pair := range ev.GetAttributes() {
		key := pair.GetKey()
		val := pair.GetValue()

		if events.IsAttributeKind(key, &beaconAPI.EpochEvent{}) {
			var event beaconAPI.EpochEvent
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
		if events.IsAttributeKind(key, &beaconAPI.VRFEvent{}) {
			var event beaconAPI.VRFEvent
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

func (sc *ServiceClient) updateCachedEpoch(height int64, epoch beaconAPI.EpochTime) bool {
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

func (sc *ServiceClient) updateCachedVRFEvent(event *beaconAPI.VRFEvent) bool {
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

func (sc *ServiceClient) currentEpochBlock() (beaconAPI.EpochTime, int64) {
	sc.RLock()
	defer sc.RUnlock()

	return sc.epoch, sc.epochCurrentBlock
}

// New constructs a new CometBFT backed beacon and epochtime backend instance.
func New(ctx context.Context, backend tmAPI.Backend) (*ServiceClient, error) {
	// Initialize and register the CometBFT service component.
	a := app.New()
	if err := backend.RegisterApplication(a); err != nil {
		return nil, err
	}

	epochCache := lru.New(lru.Capacity(epochCacheCapacity, false))

	sc := &ServiceClient{
		logger:            logging.GetLogger("cometbft/beacon"),
		querier:           a.QueryFactory().(*app.QueryFactory),
		backend:           backend,
		ctx:               ctx,
		epochLastNotified: beaconAPI.EpochInvalid,
		epochCache:        epochCache,
	}
	sc.epochNotifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
		sc.RLock()
		defer sc.RUnlock()

		if sc.epochLastNotified == sc.epoch {
			ch.In() <- sc.epoch
		}
	})
	sc.vrfNotifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
		sc.RLock()
		defer sc.RUnlock()

		if sc.vrfEvent != nil {
			ch.In() <- sc.vrfEvent
		}
	})

	genDoc, err := backend.GetGenesisDocument(ctx)
	if err != nil {
		return nil, err
	}

	sc.baseEpoch = genDoc.Beacon.Base
	sc.baseBlock = genDoc.Height

	return sc, nil
}
