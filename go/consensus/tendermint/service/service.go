// Package service provides the tendermint service interface.
package service

import (
	"context"

	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/service"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
)

// TendermintService provides Tendermint access to Oasis core backends.
type TendermintService interface {
	service.BackgroundService
	consensus.Backend

	// Started returns the channel that will be closed when the
	// tendermint service has been started.
	Started() <-chan struct{}

	// RegisterApplication registers an ABCI multiplexer application
	// with this service instance and check that its dependencies are
	// registered.
	RegisterApplication(abci.Application) error

	// SetTransactionAuthHandler configures the transaction fee handler for the
	// ABCI multiplexer.
	SetTransactionAuthHandler(abci.TransactionAuthHandler) error

	// GetGenesis will return the oasis genesis document.
	GetGenesis() *genesis.Document

	// GetHeight returns the Tendermint block height.
	GetHeight(ctx context.Context) (int64, error)

	// GetBlock returns the Tendermint block at the specified height.
	GetTendermintBlock(ctx context.Context, height int64) (*tmtypes.Block, error)

	// GetBlockResults returns the ABCI results from processing a block
	// at a specific height.
	GetBlockResults(height *int64) (*tmrpctypes.ResultBlockResults, error)

	// WatchTendermintBlocks returns a stream of Tendermint blocks as they are
	// returned via the `EventDataNewBlock` query.
	WatchTendermintBlocks() (<-chan *tmtypes.Block, *pubsub.Subscription)

	// Subscribe subscribes to tendermint events.
	Subscribe(subscriber string, query tmpubsub.Query) (tmtypes.Subscription, error)

	// Unsubscribe unsubscribes from tendermint events.
	Unsubscribe(subscriber string, query tmpubsub.Query) error
}

// GenesisProvider is a tendermint specific genesis document provider.
type GenesisProvider interface {
	GetTendermintGenesisDocument() (*tmtypes.GenesisDoc, error)
}
