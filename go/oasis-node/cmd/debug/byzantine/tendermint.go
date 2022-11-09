package byzantine

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint"
	"github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade"
)

type honestTendermint struct {
	service consensus.Backend

	genesis api.Provider
}

func newHonestTendermint(genesis api.Provider) *honestTendermint {
	return &honestTendermint{
		genesis: genesis,
	}
}

func (ht *honestTendermint) start(id *identity.Identity, dataDir string) error {
	if ht.service != nil {
		return fmt.Errorf("honest Tendermint service already started")
	}

	var err error
	ht.service, err = tendermint.New(context.Background(), dataDir, id, upgrade.NewDummyUpgradeManager(), ht.genesis)
	if err != nil {
		return fmt.Errorf("tendermint New: %w", err)
	}

	// Wait for height=1 to pass, during which mux apps perform deferred initialization.
	blockOne := make(chan struct{})
	blocksCh, blocksSub, err := ht.service.WatchBlocks(context.Background())
	if err != nil {
		return fmt.Errorf("failed to watch blocks: %w", err)
	}
	go func() {
		defer blocksSub.Close()
		for {
			block := <-blocksCh
			if block.Height > 1 {
				break
			}
		}
		close(blockOne)
	}()

	if err = ht.service.Start(); err != nil {
		return fmt.Errorf("honest Tendermint service Start: %w", err)
	}
	logger.Debug("honest Tendermint service waiting for Tendermint sync")
	<-ht.service.Synced()
	logger.Debug("honest Tendermint service sync done")
	<-blockOne
	logger.Debug("honest Tendermint block one occurred")

	return nil
}

func (ht honestTendermint) stop() error {
	if ht.service == nil {
		return fmt.Errorf("honest Tendermint service not started")
	}

	ht.service.Stop()
	logger.Debug("honest Tendermint service waiting for quit")
	<-ht.service.Quit()
	logger.Debug("honest Tendermint service quit done")

	return nil
}
