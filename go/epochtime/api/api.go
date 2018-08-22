// Package api implements the Oasis timekeeping API and common types.
package api

import (
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/pubsub"
)

// EpochTime is the number of intervals (epochs) since a fixed instant
// in time (epoch date).
type EpochTime uint64

const (
	// EkidenEpoch is the epoch date, as the number of seconds since
	// the UNIX epoch.
	EkidenEpoch int64 = 1514764800 // 2018-01-01T00:00:00+00:00

	// EpochInterval is the epoch interval in seconds.
	EpochInterval = 86400 // 1 day

	// EpochInvalid is the placeholder invalid epoch.
	EpochInvalid EpochTime = 0xffffffffffffffff // ~50 quadrillion years away.
)

// Backend is a timekeeping implementation.
type Backend interface {
	// GetEpoch returns the current epoch and the number of seconds
	// since the begining of the current epoch.
	GetEpoch(context.Context) (epoch EpochTime, elapsed uint64, err error)

	// WatchEpochs returns a channel that produces a stream of messages
	// on epoch transitions.
	//
	// Upon subscription the current epoch is sent immediately.
	WatchEpochs() (<-chan EpochTime, *pubsub.Subscription)
}

// SetableBackend is a Backend that supports setting the current epoch.
type SetableBackend interface {
	Backend

	// SetEpoch sets the current epoch and number of seconds since
	// the begining of the current epoch.
	SetEpoch(context.Context, EpochTime, uint64) error
}

// BlockBackend is a Backend that is backed by a blockchain.
type BlockBackend interface {
	Backend

	// GetBlockEpoch returns the epoch at the specified block height,
	// and the number of blocks since the begining of said epoch.
	GetBlockEpoch(context.Context, int64) (epoch EpochTime, elapsed uint64, err error)
}
