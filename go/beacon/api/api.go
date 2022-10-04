// Package api implements the random beacon and time keeping APIs.
package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
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

	// BackendVRF is the name of the VRF backend.
	BackendVRF = "vrf"
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

// EpochTimeState is the epoch state.
type EpochTimeState struct {
	Epoch  EpochTime `json:"epoch"`
	Height int64     `json:"height"`
}

// Backend is a random beacon/time keeping implementation.
type Backend interface {
	// GetBaseEpoch returns the base epoch.
	GetBaseEpoch(context.Context) (EpochTime, error)

	// GetEpoch returns the epoch number at the specified block height.
	// Calling this method with height `consensus.HeightLatest`, should
	// return the epoch of latest known block.
	GetEpoch(context.Context, int64) (EpochTime, error)

	// GetFutureEpoch returns any future epoch that is currently scheduled
	// to occur at a specific height.
	//
	// Note that this may return a nil state in case no future epoch is
	// currently scheduled.
	GetFutureEpoch(context.Context, int64) (*EpochTimeState, error)

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

	// InsecureParameters are the beacon parameters for the insecure backend.
	InsecureParameters *InsecureParameters `json:"insecure_parameters,omitempty"`

	// VRFParameters are the beacon parameters for the VRF backend.
	VRFParameters *VRFParameters `json:"vrf_parameters,omitempty"`
}

// InsecureParameters are the beacon parameters for the insecure backend.
type InsecureParameters struct {
	// Interval is the epoch interval (in blocks).
	Interval int64 `json:"interval,omitempty"`
}

// EpochEvent is the epoch event.
type EpochEvent struct {
	// Epoch is the new epoch.
	Epoch EpochTime `json:"epoch,omitempty"`
}

// EventKind returns a string representation of this event's kind.
func (ev *EpochEvent) EventKind() string {
	return "epoch"
}

// BeaconEvent is the beacon event.
type BeaconEvent struct {
	// Beacon is the new beacon value.
	Beacon []byte `json:"beacon,omitempty"`
}

// EventKind returns a string representation of this event's kind.
func (ev *BeaconEvent) EventKind() string {
	return "beacon"
}
