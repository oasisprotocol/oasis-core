// Package api implements the Oasis timekeeping API and common types.
package api

import (
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/pubsub"
)

// EpochTime is the number of intervals (epochs) since a fixed instant
// in time (epoch date).
type EpochTime uint64

// EpochInvalid is the placeholder invalid epoch.
const EpochInvalid EpochTime = 0xffffffffffffffff // ~50 quadrillion years away.

// Backend is a timekeeping implementation.
type Backend interface {
	// GetEpoch returns the current epoch.
	GetEpoch(context.Context) (epoch EpochTime, err error)

	// WatchEpochs returns a channel that produces a stream of messages
	// on epoch transitions.
	//
	// Upon subscription the current epoch is sent immediately.
	WatchEpochs() (<-chan EpochTime, *pubsub.Subscription)
}

// SetableBackend is a Backend that supports setting the current epoch.
type SetableBackend interface {
	Backend

	// SetEpoch sets the current epoch.
	SetEpoch(context.Context, EpochTime) error
}

// BlockBackend is a Backend that is backed by a blockchain.
type BlockBackend interface {
	Backend

	// GetBlockEpoch returns the epoch at the specified block height.
	GetBlockEpoch(context.Context, int64) (epoch EpochTime, err error)

	// GetEpochBlock returns the block height at the start of the said
	// epoch.
	GetEpochBlock(context.Context, EpochTime) (int64, error)
}
