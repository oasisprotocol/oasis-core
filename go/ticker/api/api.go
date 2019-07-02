// Package api implements the Oasis timekeeping API and common types.
package api

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/pubsub"
)

// TickTime is the number of intervals (ticks) since a fixed instant in time.
type TickTime uint64

// Backend is a timekeeping implementation.
type Backend interface {
	// GetTick returns the tick number at the specified block height with specified tick divisor.
	// Calling this method with height `0`, will return the tick of latest finalized block.
	GetTick(ctx context.Context, height int64, multiplier uint64) (tick TickTime, err error)

	// WatchTicks returns a channel that produces a message on every `multiplier` ticks.
	WatchTicks(multiplier uint64) (<-chan TickTime, *pubsub.Subscription)
}

// SetableBackend is a Backend that supports manually triggering ticks.
type SetableBackend interface {
	Backend

	// DoTick triggers a new tick.
	DoTick(context.Context) error
}
