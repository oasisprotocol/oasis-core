package byzantine

import (
	"context"

	"github.com/pkg/errors"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	genesis "github.com/oasislabs/oasis-core/go/genesis/file"
)

type honestTendermint struct {
	service service.TendermintService
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

	// Retrieve the genesis document and use it to configure the ChainID for
	// signature domain separation. We do this as early as possible.
	genesisDoc, err := genesis.GetGenesisDocument()
	if err != nil {
		return err
	}
	signature.SetChainContext(genesisDoc.ChainID)

	ht.service, err = tendermint.New(context.Background(), dataDir, id, genesis)
	if err != nil {
		return errors.Wrap(err, "tendermint New")
	}

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
