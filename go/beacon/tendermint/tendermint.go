// Package tendermint implementes the tendermint backed beacon backend.
package tendermint

import (
	"context"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

// BackendName is the name of this implementation.
const BackendName = "tendermint"

var (
	_ api.Backend      = (*tendermintBackend)(nil)
	_ api.BlockBackend = (*tendermintBackend)(nil)

	tendermintContext = []byte("EkB-tmnt")

	errIncoherentTime  = errors.New("beacon/tendermint: incoherent time")
	errIncompleteBlock = errors.New("beacon/tendermint: block is incomplete")
)

type tendermintBackend struct {
	sync.RWMutex

	logger *logging.Logger

	timeSource epochtime.BlockBackend
	service    service.TendermintService
	notifier   *pubsub.Broker

	cached struct {
		epoch  epochtime.EpochTime
		beacon []byte
	}
}

func (t *tendermintBackend) GetBeacon(ctx context.Context, epoch epochtime.EpochTime) ([]byte, error) {
	if epoch == epochtime.EpochInvalid {
		return nil, errIncoherentTime
	}

	if beacon := t.getCached(epoch); beacon != nil {
		return beacon, nil
	}

	return t.getBeaconImpl(ctx, epoch)
}

func (t *tendermintBackend) WatchBeacons() (<-chan *api.GenerateEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.GenerateEvent)
	sub := t.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (t *tendermintBackend) GetBlockBeacon(ctx context.Context, height int64) ([]byte, error) {
	epoch, err := t.timeSource.GetBlockEpoch(ctx, height)
	if err != nil {
		return nil, err
	}

	return t.GetBeacon(ctx, epoch)
}

func (t *tendermintBackend) getBeaconImpl(ctx context.Context, epoch epochtime.EpochTime) ([]byte, error) {
	blockHeight, err := t.timeSource.GetEpochBlock(ctx, epoch)
	if err != nil {
		t.logger.Error("failed to query epoch block height",
			"err", err,
			"epoch", epoch,
		)
		return nil, err
	}

	var entropy []byte
	switch blockHeight {
	case 0:
		entropy, err = t.getEntropyGenesis()
	default:
		entropy, err = t.getEntropyBlock(blockHeight)
	}
	if err != nil {
		t.logger.Error("failed to obtain block entropy",
			"err", err,
			"block_height", blockHeight,
		)
		return nil, err
	}

	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(epoch))

	h := sha512.New512_256()
	_, _ = h.Write(tendermintContext)
	_, _ = h.Write(entropy)
	_, _ = h.Write(tmp[:])
	ret := h.Sum(nil)

	return ret, nil
}

func (t *tendermintBackend) getEntropyGenesis() ([]byte, error) {
	res, err := t.service.Genesis()
	if err != nil {
		return nil, err
	}

	entropy := append([]byte{}, res.Genesis.AppHash...)
	entropy = append(entropy, res.Genesis.ValidatorHash()...)

	return entropy, nil
}

func (t *tendermintBackend) getEntropyBlock(blockHeight int64) ([]byte, error) {
	block, err := t.service.GetBlock(blockHeight)
	if err != nil {
		return nil, err
	}

	blockHash := block.Header.Hash()
	if blockHash == nil {
		return nil, errIncompleteBlock
	}

	return blockHash, nil
}

func (t *tendermintBackend) getCached(epoch epochtime.EpochTime) []byte {
	t.RLock()
	defer t.RUnlock()

	if t.cached.epoch != epoch {
		return nil
	}

	return append([]byte{}, t.cached.beacon...)
}

func (t *tendermintBackend) updateCached(epoch epochtime.EpochTime, beacon []byte) {
	if epoch == t.cached.epoch {
		return
	}

	t.Lock()
	t.cached.epoch = epoch
	t.cached.beacon = beacon
	t.Unlock()

	t.logger.Debug("beacon generated",
		"epoch", epoch,
		"beacon", hex.EncodeToString(beacon),
	)

	t.notifier.Broadcast(&api.GenerateEvent{
		Epoch:  epoch,
		Beacon: append([]byte{}, beacon...),
	})
}

func (t *tendermintBackend) worker(ctx context.Context) {
	// Wait for the node to be running, so that it is possible to
	// query for blocks.
	<-t.service.Started()

	ch, sub := t.timeSource.WatchEpochs()
	defer sub.Close()

	for {
		epoch, ok := <-ch
		if !ok {
			return
		}

		beacon, err := t.GetBeacon(ctx, epoch)
		if err != nil {
			t.logger.Error("failed to generate beacon for epoch",
				"err", err,
				"epoch", epoch,
			)
			continue
		}

		t.updateCached(epoch, beacon)
	}
}

// New constructs a new tendermint backed beacon Backend instance.
func New(ctx context.Context, timeSource epochtime.Backend, service service.TendermintService) (api.Backend, error) {
	if err := service.ForceInitialize(); err != nil {
		return nil, err
	}

	blockTimeSource, ok := timeSource.(epochtime.BlockBackend)
	if !ok {
		return nil, errors.New("beacon/tendermint: need a block-based epochtime backend")
	}

	t := &tendermintBackend{
		logger:     logging.GetLogger("beacon/tendermint"),
		timeSource: blockTimeSource,
		service:    service,
		notifier:   pubsub.NewBroker(true),
	}
	t.cached.epoch = epochtime.EpochInvalid

	go t.worker(ctx)

	return t, nil
}
