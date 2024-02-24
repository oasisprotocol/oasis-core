package churp

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// Backend is a CHURP management implementation.
type Backend interface {
	// Status returns the CHURP status for the specified runtime and CHURP
	// instance.
	Status(context.Context, *StatusQuery) (*Status, error)

	// Statuses returns the CHURP statuses for the specified runtime.
	Statuses(context.Context, *registry.NamespaceQuery) ([]*Status, error)

	// AllStatuses returns the CHURP statuses for all runtimes.
	AllStatuses(context.Context, int64) ([]*Status, error)

	// WatchStatuses returns a channel that produces a stream of messages
	// containing CHURP statuses as they change over time.
	//
	// Upon subscription the current statuses are sent immediately.
	WatchStatuses() (<-chan *Status, *pubsub.Subscription)
}
