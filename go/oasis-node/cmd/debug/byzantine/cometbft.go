package byzantine

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade"
)

type honestCometBFT struct {
	service consensus.Service

	genesis    genesis.Provider
	genesisDoc *genesis.Document
}

func newHonestCometBFT(genesis genesis.Provider, genesisDoc *genesis.Document) *honestCometBFT {
	return &honestCometBFT{
		genesis:    genesis,
		genesisDoc: genesisDoc,
	}
}

func (ht *honestCometBFT) start(id *identity.Identity, dataDir string) error {
	if ht.service != nil {
		return fmt.Errorf("honest CometBFT service already started")
	}

	var err error
	ht.service, err = cometbft.New(context.Background(), dataDir, id, upgrade.NewDummyUpgradeManager(), ht.genesis, ht.genesisDoc)
	if err != nil {
		return fmt.Errorf("cometbft New: %w", err)
	}

	// Wait for height=1 to pass, during which mux apps perform deferred initialization.
	blockOne := make(chan struct{})
	blocksCh, blocksSub, err := ht.service.Core().WatchBlocks(context.Background())
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
		return fmt.Errorf("honest CometBFT service Start: %w", err)
	}
	logger.Debug("honest CometBFT service waiting for CometBFT sync")
	<-ht.service.Synced()
	logger.Debug("honest CometBFT service sync done")
	<-blockOne
	logger.Debug("honest CometBFT block one occurred")

	return nil
}

func (ht honestCometBFT) stop() error {
	if ht.service == nil {
		return fmt.Errorf("honest CometBFT service not started")
	}

	ht.service.Stop()
	logger.Debug("honest CometBFT service waiting for quit")
	<-ht.service.Quit()
	logger.Debug("honest CometBFT service quit done")

	return nil
}
