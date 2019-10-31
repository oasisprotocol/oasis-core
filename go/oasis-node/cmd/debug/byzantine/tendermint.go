package byzantine

import (
	"context"
	"time"

	"github.com/pkg/errors"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/genesis"
	"github.com/oasislabs/oasis-core/go/tendermint"
	beaconapp "github.com/oasislabs/oasis-core/go/tendermint/apps/beacon"
	epochtimemockapp "github.com/oasislabs/oasis-core/go/tendermint/apps/epochtime_mock"
	keymanagerapp "github.com/oasislabs/oasis-core/go/tendermint/apps/keymanager"
	registryapp "github.com/oasislabs/oasis-core/go/tendermint/apps/registry"
	roothashapp "github.com/oasislabs/oasis-core/go/tendermint/apps/roothash"
	schedulerapp "github.com/oasislabs/oasis-core/go/tendermint/apps/scheduler"
	stakingapp "github.com/oasislabs/oasis-core/go/tendermint/apps/staking"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

var _ epochtime.Backend = (*fakeTimeBackend)(nil)

// fakeTimeBackend is like TendermintBackend (of epochtime), but without
// any workers.
type fakeTimeBackend struct {
	service *honestTendermint

	useMockEpochTime bool
}

// GetBaseEpoch implements epochtime Backend.
func (t *fakeTimeBackend) GetBaseEpoch(ctx context.Context) (epochtime.EpochTime, error) {
	// XXX: This will need to honor the base epoch if this is ever used in
	// conjunction with the real timekeeping backend, and a dump/restore.
	return 0, nil
}

// GetEpoch implements epochtime Backend.
func (t *fakeTimeBackend) GetEpoch(ctx context.Context, height int64) (epochtime.EpochTime, error) {
	if height == 0 {
		panic("0 height not supported")
	}

	if t.useMockEpochTime {
		// Query the epochtime_mock Tendermint application.
		q, err := t.service.epochtimeMockQuery.QueryAt(ctx, height)
		if err != nil {
			return epochtime.EpochInvalid, errors.Wrap(err, "epochtime: epoch query failed")
		}

		epoch, _, err := q.Epoch(ctx)
		if err != nil {
			return epochtime.EpochInvalid, errors.Wrap(err, "epochtime: epoch query failed")
		}
		return epoch, nil
	}

	// Use the the epoch interval that we have in E2E tests.
	// We could make this more flexible with command line flags in future work.
	return epochtime.EpochTime(height / 30), nil
}

// GetEpochBlock implements epochtime Backend.
func (*fakeTimeBackend) GetEpochBlock(ctx context.Context, epoch epochtime.EpochTime) (int64, error) {
	panic("GetEpochBlock not supported")
}

// WatchEpochs implements epochtime Backend.
func (*fakeTimeBackend) WatchEpochs() (<-chan epochtime.EpochTime, *pubsub.Subscription) {
	panic("WatchEpochs not supported")
}

func (*fakeTimeBackend) ToGenesis(ctx context.Context, height int64) (*epochtime.Genesis, error) {
	panic("ToGenesis not supported")
}

type honestTendermint struct {
	service service.TendermintService

	schedulerQuery     *schedulerapp.QueryFactory
	roothashQuery      *roothashapp.QueryFactory
	registryQuery      *registryapp.QueryFactory
	epochtimeMockQuery *epochtimemockapp.QueryFactory
}

func newHonestTendermint() *honestTendermint {
	return &honestTendermint{}
}

func (ht *honestTendermint) start(id *identity.Identity, dataDir string, useMockEpochTime bool) error {
	if ht.service != nil {
		return errors.New("honest Tendermint service already started")
	}

	genesis, err := genesis.New()
	if err != nil {
		return errors.Wrap(err, "genesis New")
	}
	ht.service, err = tendermint.New(context.Background(), dataDir, id, genesis)
	if err != nil {
		return errors.Wrap(err, "tendermint New")
	}

	if err = ht.service.ForceInitialize(); err != nil {
		return errors.Wrap(err, "honest Tendermint service ForceInitialize")
	}

	// Register honest mux apps.
	// This isn't very flexible. It's configured to match what we use in end-to-end tests.
	// And we do that mostly by hardcoding options. We could make this more flexible with command
	// line flags in future work.
	timeSource := &fakeTimeBackend{
		service:          ht,
		useMockEpochTime: useMockEpochTime,
	}
	if useMockEpochTime {
		epochtimeMockApp := epochtimemockapp.New()
		if err = ht.service.RegisterApplication(epochtimeMockApp); err != nil {
			return errors.Wrap(err, "honest Tendermint service RegisterApplication epochtime_mock")
		}
		ht.epochtimeMockQuery = epochtimeMockApp.QueryFactory().(*epochtimemockapp.QueryFactory)
	}
	if err = ht.service.RegisterApplication(beaconapp.New(timeSource)); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication beacon")
	}
	if err = ht.service.RegisterApplication(stakingapp.New(timeSource)); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication staking")
	}
	registryApp := registryapp.New(timeSource)
	if err = ht.service.RegisterApplication(registryApp); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication registry")
	}
	ht.registryQuery = registryApp.QueryFactory().(*registryapp.QueryFactory)
	if err = ht.service.RegisterApplication(keymanagerapp.New(timeSource)); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication keymanager")
	}
	schedApp, err := schedulerapp.New(timeSource)
	if err != nil {
		return errors.Wrap(err, "honest Tendermint service New scheduler")
	}
	if err = ht.service.RegisterApplication(schedApp); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication scheduler")
	}
	ht.schedulerQuery = schedApp.QueryFactory().(*schedulerapp.QueryFactory)
	// storage has no registration
	roothashApp := roothashapp.New(timeSource, nil, 10*time.Second)
	if err = ht.service.RegisterApplication(roothashApp); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication roothash")
	}
	ht.roothashQuery = roothashApp.QueryFactory().(*roothashapp.QueryFactory)

	// Wait for height=1 to pass, during which mux apps perform deferred initialization.
	blockOne := make(chan struct{})
	blocksCh, blocksSub := ht.service.WatchBlocks()
	go func() {
		defer blocksSub.Close()
		for {
			block := <-blocksCh
			if block.Header.Height > 1 {
				break
			}
		}
		close(blockOne)
	}()

	if err = ht.service.Start(); err != nil {
		return errors.Wrap(err, "honest Tendermint service Start")
	}
	logger.Debug("honest Tendermint service waiting for Tendermint start")
	<-ht.service.Started()
	logger.Debug("honest Tendermint service waiting for Tendermint sync")
	<-ht.service.Synced()
	logger.Debug("honest Tendermint service sync done")
	<-blockOne
	logger.Debug("honest Tendermint block one occurred")

	return nil
}

func (ht honestTendermint) stop() error {
	if ht.service == nil {
		return errors.New("honest Tendermint service not started")
	}

	ht.service.Stop()
	logger.Debug("honest Tendermint service waiting for quit")
	<-ht.service.Quit()
	logger.Debug("honest Tendermint service quit done")
	ht.service = nil

	return nil
}

// tendermintUnsubscribeDrain drains an unbuffered subscription while unsubscribing.
func tendermintUnsubscribeDrain(svc service.TendermintService, subscriber string, query tmpubsub.Query, sub tmtypes.Subscription) error {
	go func() {
		for {
			select {
			case <-sub.Out():
			case <-sub.Cancelled():
				break
			}
		}
	}()
	if err := svc.Unsubscribe("script", query); err != nil {
		return errors.Wrap(err, "Tendermint Unsubscribe")
	}

	return nil
}

// tendermintBroadcastTxCommit is like Tendermint's own BroadcastTxCommit, but without
// the timeout system.
func tendermintBroadcastTxCommit(svc service.TendermintService, tag byte, tx interface{}) error {
	if err := svc.BroadcastTx(context.Background(), tag, tx, true); err != nil {
		return errors.Wrap(err, "Tendermint BroadcastTx")
	}

	return nil
}
