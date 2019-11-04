package byzantine

import (
	"context"

	"github.com/pkg/errors"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/identity"
	genesis "github.com/oasislabs/oasis-core/go/genesis/file"
	"github.com/oasislabs/oasis-core/go/tendermint"
	beaconapp "github.com/oasislabs/oasis-core/go/tendermint/apps/beacon"
	keymanagerapp "github.com/oasislabs/oasis-core/go/tendermint/apps/keymanager"
	registryapp "github.com/oasislabs/oasis-core/go/tendermint/apps/registry"
	roothashapp "github.com/oasislabs/oasis-core/go/tendermint/apps/roothash"
	schedulerapp "github.com/oasislabs/oasis-core/go/tendermint/apps/scheduler"
	stakingapp "github.com/oasislabs/oasis-core/go/tendermint/apps/staking"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

type honestTendermint struct {
	service service.TendermintService

	schedulerQuery *schedulerapp.QueryFactory
	roothashQuery  *roothashapp.QueryFactory
	registryQuery  *registryapp.QueryFactory
}

func newHonestTendermint() *honestTendermint {
	return &honestTendermint{}
}

func (ht *honestTendermint) start(id *identity.Identity, dataDir string) error {
	if ht.service != nil {
		return errors.New("honest Tendermint service already started")
	}

	genesis, err := genesis.DefaultFileProvider()
	if err != nil {
		return errors.Wrap(err, "genesis DefaultFileProvider")
	}
	ht.service, err = tendermint.New(context.Background(), dataDir, id, genesis)
	if err != nil {
		return errors.Wrap(err, "tendermint New")
	}

	// Register honest mux apps.
	if err = ht.service.RegisterApplication(beaconapp.New()); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication beacon")
	}
	if err = ht.service.RegisterApplication(stakingapp.New()); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication staking")
	}
	registryApp := registryapp.New()
	if err = ht.service.RegisterApplication(registryApp); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication registry")
	}
	ht.registryQuery = registryApp.QueryFactory().(*registryapp.QueryFactory)
	if err = ht.service.RegisterApplication(keymanagerapp.New()); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication keymanager")
	}
	schedApp, err := schedulerapp.New()
	if err != nil {
		return errors.Wrap(err, "honest Tendermint service New scheduler")
	}
	if err = ht.service.RegisterApplication(schedApp); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication scheduler")
	}
	ht.schedulerQuery = schedApp.QueryFactory().(*schedulerapp.QueryFactory)
	// storage has no registration
	roothashApp := roothashapp.New(nil)
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
