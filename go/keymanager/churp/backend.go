package churp

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// Backend is a CHURP management implementation.
type Backend interface {
	// ConsensusParameters returns the CHURP consensus parameters.
	ConsensusParameters(context.Context, int64) (*ConsensusParameters, error)

	// Status returns the CHURP status for the specified runtime and CHURP
	// scheme.
	Status(context.Context, *StatusQuery) (*Status, error)

	// Statuses returns the CHURP statuses for the specified runtime.
	Statuses(context.Context, *registry.NamespaceQuery) ([]*Status, error)

	// AllStatuses returns the CHURP statuses for all runtimes.
	AllStatuses(context.Context, int64) ([]*Status, error)

	// WatchStatuses returns a channel that produces a stream of messages
	// containing CHURP statuses as they change over time.
	//
	// Upon subscription the current statuses are sent immediately.
	WatchStatuses(context.Context) (<-chan *Status, pubsub.ClosableSubscription, error)

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(context.Context, int64) (*Genesis, error)
}

// Genesis is the key manager management genesis state for CHURP.
type Genesis struct {
	// Parameters are the consensus parameters for CHURP.
	Parameters ConsensusParameters `json:"params"`

	// Statuses are the statuses of CHURP instances.
	Statuses []*Status `json:"statuses,omitempty"`
}
