// Package api implements the Oasis timekeeping API and common types.
package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/pubsub"
)

// EpochTime is the number of intervals (epochs) since a fixed instant
// in time (epoch date).
type EpochTime uint64

// EpochInvalid is the placeholder invalid epoch.
const EpochInvalid EpochTime = 0xffffffffffffffff // ~50 quadrillion years away.

// Backend is a timekeeping implementation.
type Backend interface {
	// GetBaseEPoch returns the base epoch.
	GetBaseEpoch(context.Context) (EpochTime, error)

	// GetEpoch returns the epoch at the specified block height.
	// Calling this method with height `0`, should return the
	// epoch of latest known block.
	GetEpoch(context.Context, int64) (EpochTime, error)

	// GetEpochBlock returns the block height at the start of the said
	// epoch.
	GetEpochBlock(context.Context, EpochTime) (int64, error)

	// WatchEpochs returns a channel that produces a stream of messages
	// on epoch transitions.
	//
	// Upon subscription the current epoch is sent immediately.
	WatchEpochs() (<-chan EpochTime, *pubsub.Subscription)

	// ToGenesis returns the genesis state at the specified block height.
	ToGenesis(ctx context.Context, height int64) (*Genesis, error)
}

// SetableBackend is a Backend that supports setting the current epoch.
type SetableBackend interface {
	Backend

	// SetEpoch sets the current epoch.
	SetEpoch(context.Context, EpochTime) error
}

// Genesis is the initial genesis state for allowing configurable timekeeping.
type Genesis struct {
	// Parameters are the epochtime consensus parameters.
	Parameters ConsensusParameters `json:"params"`

	// Base is the starting epoch.
	Base EpochTime `json:"base"`
}

// ConsensusParameters are the epochtime consensus parameters.
type ConsensusParameters struct {
	// Interval is the epoch interval (in blocks).
	Interval int64 `json:"interval"`

	// Backend is the chosen epochtime backend.
	// TODO: Change this to a simple DebugMockBackend bool flag (probably in #1879).
	Backend string `json:"backend"`
}
