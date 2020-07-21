// XXX: This should be moved to go/consensus/tendermint/api.
// Package service provides the tendermint service interface.
package service

import (
	"context"

	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
)

// TendermintService provides Tendermint access to Oasis core backends.
type TendermintService interface {
	consensus.Backend

	// RegisterApplication registers an ABCI multiplexer application
	// with this service instance and check that its dependencies are
	// registered.
	RegisterApplication(abci.Application) error

	// SetTransactionAuthHandler configures the transaction fee handler for the
	// ABCI multiplexer.
	SetTransactionAuthHandler(abci.TransactionAuthHandler) error

	// GetBlock returns the Tendermint block at the specified height.
	GetTendermintBlock(ctx context.Context, height int64) (*tmtypes.Block, error)

	// GetBlockResults returns the ABCI results from processing a block
	// at a specific height.
	GetBlockResults(height int64) (*tmrpctypes.ResultBlockResults, error)

	// WatchTendermintBlocks returns a stream of Tendermint blocks as they are
	// returned via the `EventDataNewBlock` query.
	WatchTendermintBlocks() (<-chan *tmtypes.Block, *pubsub.Subscription)
}
