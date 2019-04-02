// Package service provides the tendermint service interface.
package service

import (
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

// TendermintService provides Tendermint access to Ekiden backends.
type TendermintService interface {
	service.BackgroundService

	// Started returns the channel that will be closed when the
	// tendermint service has been started.
	Started() <-chan struct{}

	// Synced returns the channel that will be closed when the
	// tendermint service finishes fast sync.
	Synced() <-chan struct{}

	// RegisterApplication registers an ABCI multiplexer application
	// with this service instance.
	RegisterApplication(abci.Application) error

	// ForceInitialize force-initializes the Tendermint service iff
	// it has not been started.  Otherwise the routine has no effect
	// and will succeed.
	ForceInitialize() error

	// GetBlock returns the Tendermint block at the specified height.
	GetBlock(height int64) (*tmtypes.Block, error)

	// GetBlockResults returns the ABCI results from processing a block
	// at a specific height.
	GetBlockResults(height int64) (*tmrpctypes.ResultBlockResults, error)

	// WatchBlocks returns a stream of Tendermint blocks as they are
	// returned via the `EventDataNewBlock` query.
	WatchBlocks() (<-chan *tmtypes.Block, *pubsub.Subscription)

	// NodeKey returns the node's P2P (link) authentication public key.
	NodeKey() *signature.PublicKey

	// BroadcastTx broadcasts a transaction for Ekiden ABCI application.
	//
	// The CBOR-encodable transaction together with the given application
	// tag is first marshalled and then transmitted using BroadcastTxCommit.
	BroadcastTx(tag byte, tx interface{}) error

	// Query performs a query against the tendermint application.
	Query(path string, query interface{}, height int64) ([]byte, error)

	// Subscribe subscribes to tendermint events.
	Subscribe(subscriber string, query tmpubsub.Query) (tmtypes.Subscription, error)

	// Unsubscribe unsubscribes from tendermint events.
	Unsubscribe(subscriber string, query tmpubsub.Query) error

	// Genesis returns the tendermint genesis block information.
	Genesis() (*tmrpctypes.ResultGenesis, error)
}
