// Package consensus provides the implementation agnostic consensus
// backend.
package consensus

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/node"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesisAPI "github.com/oasislabs/oasis-core/go/genesis/api"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

// Backend is an interface that a consensus backend must provide.
type Backend interface {
	// Synced returns a channel that is closed once synchronization is
	// complete.
	Synced() <-chan struct{}

	// ConsensusKey returns the consensus signing key.
	ConsensusKey() signature.PublicKey

	// GetAddresses returns the consensus backend addresses.
	GetAddresses() ([]node.ConsensusAddress, error)

	// RegisterGenesisHook registers a function to be called when the
	// consensus backend is initialized from genesis (e.g., on fresh
	// start).
	//
	// Note that these hooks block consensus genesis from completing
	// while they are running.
	RegisterGenesisHook(func())

	// RegisterHaltHook registers a function to be called when the
	// consensus Halt epoch height is reached.
	RegisterHaltHook(func(ctx context.Context, blockHeight int64, epoch epochtime.EpochTime))

	// EpochTime returns the epochtime backend.
	// XXX: with https://github.com/oasislabs/oasis-core/issues/1879 do similar
	// for other backends.
	EpochTime() epochtime.Backend

	// ToGenesis returns the genesis state at the specified block height.
	// XXX: with #1879 the ToGenesis all the backend arguments can be removed.
	ToGenesis(ctx context.Context, blockHeight int64, km keymanager.Backend, reg registry.Backend, rh roothash.Backend, s staking.Backend, sch scheduler.Backend) (*genesisAPI.Document, error)
}
