package byzantine

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/file"
	"github.com/oasisprotocol/oasis-core/go/upgrade"
)

type honestTendermint struct {
	service consensus.Backend
}

func newHonestTendermint() *honestTendermint {
	return &honestTendermint{}
}

func (ht *honestTendermint) start(id *identity.Identity, dataDir string) error {
	if ht.service != nil {
		return fmt.Errorf("honest Tendermint service already started")
	}

	genesis, err := genesis.DefaultFileProvider()
	if err != nil {
		return fmt.Errorf("genesis DefaultFileProvider: %w", err)
	}

	// Retrieve the genesis document and use it to configure the ChainID for
	// signature domain separation. We do this as early as possible.
	genesisDoc, err := genesis.GetGenesisDocument()
	if err != nil {
		return err
	}
	genesisDoc.SetChainContext()

	ht.service, err = tendermint.New(context.Background(), dataDir, id, upgrade.NewDummyUpgradeManager(), genesis)
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
