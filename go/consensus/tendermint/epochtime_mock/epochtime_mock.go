// Package epochtimemock implements the mock (settable) tendermint backed epochtime backend.
package epochtimemock

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/eapache/channels"
	tmabcitypes "github.com/tendermint/tendermint/abci/types"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/epochtime_mock"
	"github.com/oasisprotocol/oasis-core/go/epochtime/api"
)

var testSigner signature.Signer

// ServiceClient is the beacon service client interface.
type ServiceClient interface {
	api.Backend
	tmapi.ServiceClient
}

type serviceClient struct {
	tmapi.BaseServiceClient
	sync.RWMutex

	logger *logging.Logger

	backend  tmapi.Backend
	querier  *app.QueryFactory
	notifier *pubsub.Broker

	lastNotified  api.EpochTime
	epoch         api.EpochTime
	currentBlock  int64
	initialNotify bool
}

func (sc *serviceClient) GetBaseEpoch(context.Context) (api.EpochTime, error) {
	return 0, nil
}

func (sc *serviceClient) GetEpoch(ctx context.Context, height int64) (api.EpochTime, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return api.EpochInvalid, err
	}

	epoch, _, err := q.Epoch(ctx)
	return epoch, err
}

func (sc *serviceClient) GetEpochBlock(ctx context.Context, epoch api.EpochTime) (int64, error) {
	sc.RLock()
	defer sc.RUnlock()

	if epoch == sc.epoch {
		return sc.currentBlock, nil
	}

	// Find historic epoch -- it is fine if this is not optimal as mock epochtime is only for tests
	// where the number of epoch transitions shoud be low.
	height := consensus.HeightLatest
	for {
		q, err := sc.querier.QueryAt(ctx, height)
		if err != nil {
			return -1, fmt.Errorf("failed to query epoch: %w", err)
		}

		var pastEpoch api.EpochTime
		pastEpoch, height, err = q.Epoch(ctx)
		if err != nil {
			return -1, fmt.Errorf("failed to query epoch: %w", err)
		}

		if epoch == pastEpoch {
			return height, nil
		}

		height--

		if pastEpoch == 0 || height <= 1 {
			return -1, fmt.Errorf("failed to find historic epoch (minimum: %d requested: %d)", pastEpoch, epoch)
		}
	}
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
	now, err := sc.GetEpoch(ctx, height)
	if err != nil {
		return nil, err
	}

	return &api.Genesis{
		Parameters: api.ConsensusParameters{
			DebugMockBackend: true,
		},
		Base: now,
	}, nil
}

func (sc *serviceClient) SetEpoch(ctx context.Context, epoch api.EpochTime) error {
	ch, sub := sc.WatchEpochs()
	defer sub.Close()

	tx := transaction.NewTransaction(0, nil, app.MethodSetEpoch, epoch)
	if err := consensus.SignAndSubmitTx(ctx, sc.backend, testSigner, tx); err != nil {
		return fmt.Errorf("epochtime: set epoch failed: %w", err)
	}

	for {
		select {
		case newEpoch, ok := <-ch:
			if !ok {
				return context.Canceled
			}
			if newEpoch == epoch {
				return nil
			}
		case <-ctx.Done():
			return context.Canceled
		}
	}
}

// Implements api.ServiceClient.
func (sc *serviceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []tmpubsub.Query{app.QueryApp})
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverBlock(ctx context.Context, height int64) error {
	if !sc.initialNotify {
		q, err := sc.querier.QueryAt(ctx, height)
		if err != nil {
			return fmt.Errorf("epochtime_mock: failed to query epoch: %w", err)
		}

		var epoch api.EpochTime
		epoch, height, err = q.Epoch(ctx)
		if err != nil {
			return fmt.Errorf("epochtime_mock: failed to query epoch: %w", err)
		}

		if sc.updateCached(height, epoch) {
			sc.notifier.Broadcast(epoch)
		}
		sc.initialNotify = true
	}
	return nil
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverEvent(ctx context.Context, height int64, tx tmtypes.Tx, ev *tmabcitypes.Event) error {
	for _, pair := range ev.GetAttributes() {
		if bytes.Equal(pair.GetKey(), app.KeyEpoch) {
			var epoch api.EpochTime
			if err := cbor.Unmarshal(pair.GetValue(), &epoch); err != nil {
				sc.logger.Error("epochtime_mock: malformed mock epoch",
					"err", err,
				)
				continue
			}

			if sc.updateCached(height, epoch) {
				sc.notifier.Broadcast(sc.epoch)
			}
		}
	}
	return nil
}

func (sc *serviceClient) updateCached(height int64, epoch api.EpochTime) bool {
	sc.Lock()
	defer sc.Unlock()

	sc.epoch = epoch
	sc.currentBlock = height

	if sc.lastNotified != epoch {
		sc.logger.Debug("epoch transition",
			"prev_epoch", sc.lastNotified,
			"epoch", epoch,
			"height", height,
		)
		sc.lastNotified = sc.epoch
		return true
	}
	return false
}

// New constructs a new mock tendermint backed epochtime Backend instance.
func New(ctx context.Context, backend tmapi.Backend) (ServiceClient, error) {
	// Initialize and register the tendermint service component.
	a := app.New()
	if err := backend.RegisterApplication(a); err != nil {
		return nil, err
	}

	sc := &serviceClient{
		logger:  logging.GetLogger("epochtime/tendermint_mock"),
		backend: backend,
		querier: a.QueryFactory().(*app.QueryFactory),
	}
	sc.notifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
		sc.RLock()
		defer sc.RUnlock()

		if sc.lastNotified == sc.epoch {
			ch.In() <- sc.epoch
		}
	})

	genDoc, err := backend.GetGenesisDocument(ctx)
	if err != nil {
		return nil, err
	}

	if base := genDoc.EpochTime.Base; base != 0 {
		sc.logger.Warn("ignoring non-zero base genesis epoch",
			"base", base,
		)
	}

	return sc, nil
}

func init() {
	testSigner = memorySigner.NewTestSigner("oasis-core epochtime mock key seed")
}
