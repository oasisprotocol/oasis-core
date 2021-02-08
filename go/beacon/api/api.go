// Package api implements the random beacon and time keeping APIs.
package api

import (
	"context"
	"fmt"
	"math"

	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
)

const (
	// ModuleName is a unique module name for the beacon module.
	ModuleName = "beacon"

	// BeaconSize is the size of the beacon in bytes.
	BeaconSize = 32

	// EpochInvalid is the placeholder invalid epoch.
	EpochInvalid EpochTime = 0xffffffffffffffff // ~50 quadrillion years away.

	// BackendInsecure is the name of the insecure backend.
	BackendInsecure = "insecure"

	// BackendPVSS is the name of the PVSS backend.
	BackendPVSS = "pvss"
)

// ErrBeaconNotAvailable is the error returned when a beacon is not
// available for the requested height for any reason.
var ErrBeaconNotAvailable = errors.New(ModuleName, 1, "beacon: random beacon not available")

// EpochTime is the number of intervals (epochs) since a fixed instant
// in time/block height (epoch date/height).
type EpochTime uint64

// AbsDiff returns the absolute difference (in epochs) between two epochtimes.
func (e EpochTime) AbsDiff(other EpochTime) EpochTime {
	if e > other {
		return e - other
	}
	return other - e
}

// Backend is a random beacon/time keeping implementation.
type Backend interface {
	// GetBaseEpoch returns the base epoch.
	GetBaseEpoch(context.Context) (EpochTime, error)

	// GetEpoch returns the epoch number at the specified block height.
	// Calling this method with height `consensus.HeightLatest`, should
	// return the epoch of latest known block.
	GetEpoch(context.Context, int64) (EpochTime, error)

	// GetEpochBlock returns the block height at the start of the said
	// epoch.
	GetEpochBlock(context.Context, EpochTime) (int64, error)

	// WaitEpoch waits for a specific epoch.
	//
	// Note that an epoch is considered reached even if any epoch greater
	// than the one specified is reached (e.g., that the current epoch
	// is already in the future).
	WaitEpoch(ctx context.Context, epoch EpochTime) error

	// WatchEpochs returns a channel that produces a stream of messages
	// on epoch transitions.
	//
	// Upon subscription the current epoch is sent immediately.
	WatchEpochs(ctx context.Context) (<-chan EpochTime, pubsub.ClosableSubscription, error)

	// WatchLatestEpoch returns a channel that produces a stream of
	// messages on epoch transitions. If an epoch transition happens
	// before the previous epoch is read from the channel, the old
	// epochs are overwritten.
	//
	// Upon subscription the current epoch is sent immediately.
	WatchLatestEpoch(ctx context.Context) (<-chan EpochTime, pubsub.ClosableSubscription, error)

	// GetBeacon gets the beacon for the provided block height.
	// Calling this method with height `consensus.HeightLatest` should
	// return the beacon for the latest finalized block.
	GetBeacon(context.Context, int64) ([]byte, error)

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(context.Context, int64) (*Genesis, error)

	// ConsensusParameters returns the beacon consensus parameters.
	ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error)
}

// SetableBackend is a Backend that supports setting the current epoch.
type SetableBackend interface {
	Backend

	// SetEpoch sets the current epoch.
	SetEpoch(context.Context, EpochTime) error
}

// Genesis is the genesis state.
type Genesis struct {
	// Base is the starting epoch.
	Base EpochTime `json:"base"`

	// Parameters are the beacon consensus parameters.
	Parameters ConsensusParameters `json:"params"`
}

// ConsensusParameters are the beacon consensus parameters.
type ConsensusParameters struct {
	// Backend is the beacon backend.
	Backend string `json:"backend"`

	// DebugMockBackend is flag for enabling the mock epochtime backend.
	DebugMockBackend bool `json:"debug_mock_backend,omitempty"`

	// DebugDeterministic is true iff the output should be deterministic.
	DebugDeterministic bool `json:"debug_deterministic,omitempty"`

	// InsecureParameters are the beacon parameters for the insecure backend.
	InsecureParameters *InsecureParameters `json:"insecure_parameters,omitempty"`

	// PVSSParameters are the beacon parameters for the PVSS backend.
	PVSSParameters *PVSSParameters `json:"pvss_parameters,omitempty"`
}

// InsecureParameters are the beacon parameters for the insecure backend.
type InsecureParameters struct {
	// Interval is the epoch interval (in blocks).
	Interval int64 `json:"interval,omitempty"`
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	switch g.Parameters.Backend {
	case BackendInsecure:
		params := g.Parameters.InsecureParameters
		if params == nil {
			return fmt.Errorf("beacon: sanity check failed: insecure backend not configured")
		}

		if params.Interval <= 0 && !g.Parameters.DebugMockBackend {
			return fmt.Errorf("beacon: sanity check failed: epoch interval must be > 0")
		}
	case BackendPVSS:
		params := g.Parameters.PVSSParameters
		if params == nil {
			return fmt.Errorf("beacon: sanity check failed: PVSS backend not configured")
		}

		if params.Participants <= 1 {
			return fmt.Errorf("beacon: sanity check failed: PVSS participants must be > 1")
		}
		if params.Participants > math.MaxInt32 {
			return fmt.Errorf("beacon: sanity check failed: PVSS participants must be < %d", math.MaxInt32)
		}
		if n := params.Threshold; n <= 1 || n > params.Participants {
			return fmt.Errorf("beacon: sanity check failed: PVSS threshold must be > 1 and <= participants")
		}

		if params.CommitInterval <= 0 {
			return fmt.Errorf("beacon: sanity check failed: PVSS commit interval must be > 0")
		}
		if params.RevealInterval <= 0 {
			return fmt.Errorf("beacon: sanity check failed: PVSS reveal interval must be > 0")
		}
		if params.TransitionDelay <= 0 {
			return fmt.Errorf("beacon: sanity check failed: PVSS transition delay must be > 0")
		}
		if len(params.DebugForcedParticipants) > 0 && !flags.DebugDontBlameOasis() {
			return fmt.Errorf("beacon: sanity check failed: PVSS forced participants set")
		}
	default:
		return fmt.Errorf("beacon: sanity check failed: unknown backend: '%s'", g.Parameters.Backend)
	}

	unsafeFlags := g.Parameters.DebugMockBackend || g.Parameters.DebugDeterministic
	if unsafeFlags && !flags.DebugDontBlameOasis() {
		return fmt.Errorf("beacon: sanity check failed: one or more unsafe debug flags set")
	}

	if g.Base == EpochInvalid {
		return fmt.Errorf("beacon: sanity check failed: starting epoch is invalid")
	}

	return nil
}
