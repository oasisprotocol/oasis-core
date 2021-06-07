package api

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/pvss"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
)

var (
	// MethodPVSSCommit is the method name for a PVSS commitment.
	MethodPVSSCommit = transaction.NewMethodName(ModuleName, "PVSSCommit", PVSSCommit{})

	// MethodPVSSReveal is the method name for a PVSS reveal.
	MethodPVSSReveal = transaction.NewMethodName(ModuleName, "PVSSReveal", PVSSReveal{})
)

// PVSSParameters are the beacon parameters for the PVSS backend.
type PVSSParameters struct {
	Participants uint32 `json:"participants"`
	Threshold    uint32 `json:"threshold"`

	CommitInterval  int64 `json:"commit_interval"`
	RevealInterval  int64 `json:"reveal_interval"`
	TransitionDelay int64 `json:"transition_delay"`

	DebugForcedParticipants []signature.PublicKey `json:"debug_forced_participants,omitempty"`
}

// PVSSCommit is a PVSS commitment transaction payload.
type PVSSCommit struct {
	Epoch EpochTime `json:"epoch"`
	Round uint64    `json:"round"`

	Commit *pvss.Commit `json:"commit,omitempty"`
}

// Implements transaction.MethodMetadataProvider.
func (pc PVSSCommit) MethodMetadata() transaction.MethodMetadata {
	return transaction.MethodMetadata{
		// Beacon transactions are critical to protocol operation. Since they can only be called
		// by the block proposer this is safe to use.
		Priority: transaction.MethodPriorityCritical,
	}
}

// PVSSReveal is a PVSS reveal transaction payload.
type PVSSReveal struct {
	Epoch EpochTime `json:"epoch"`
	Round uint64    `json:"round"`

	Reveal *pvss.Reveal `json:"reveal,omitempty"`
}

// Implements transaction.MethodMetadataProvider.
func (pr PVSSReveal) MethodMetadata() transaction.MethodMetadata {
	return transaction.MethodMetadata{
		// Beacon transactions are critical to protocol operation. Since they can only be called
		// by the block proposer this is safe to use.
		Priority: transaction.MethodPriorityCritical,
	}
}

// RoundState is a PVSS round state.
type RoundState uint8

const (
	StateInvalid  RoundState = 0
	StateCommit   RoundState = 1
	StateReveal   RoundState = 2
	StateComplete RoundState = 3
)

func (s RoundState) String() string {
	switch s {
	case StateInvalid:
		return "invalid"
	case StateCommit:
		return "commit"
	case StateReveal:
		return "reveal"
	case StateComplete:
		return "complete"
	default:
		return fmt.Sprintf("[invalid state: %d]", s)
	}
}

// PVSSState is the PVSS backend state.
type PVSSState struct {
	Height int64 `json:"height,omitempty"`

	Epoch EpochTime  `json:"epoch,omitempty"`
	Round uint64     `json:"round,omitempty"`
	State RoundState `json:"state,omitempty"`

	Instance     *pvss.Instance        `json:"instance,omitempty"`
	Participants []signature.PublicKey `json:"participants,omitempty"`
	Entropy      []byte                `json:"entropy,omitempty"`

	BadParticipants map[signature.PublicKey]bool `json:"bad_participants,omitempty"`

	CommitDeadline   int64 `json:"commit_deadline,omitempty"`
	RevealDeadline   int64 `json:"reveal_deadline,omitempty"`
	TransitionHeight int64 `json:"transition_height,omitempty"`

	RuntimeDisableHeight int64 `json:"runtime_disable_height,omitempty"`
}

// PVSSEvent is a PVSS backend event.
type PVSSEvent struct {
	Height int64 `json:"height,omitempty"`

	Epoch EpochTime  `json:"epoch,omitempty"`
	Round uint64     `json:"round,omitempty"`
	State RoundState `json:"state,omitempty"`

	Participants []signature.PublicKey `json:"participants,omitempty"`
}

func (ev *PVSSEvent) FromState(state *PVSSState) {
	ev.Height = state.Height
	ev.Epoch = state.Epoch
	ev.Round = state.Round
	ev.State = state.State
	ev.Participants = state.Participants
}

// PVSSBackend is a Backend that is backed by PVSS.
type PVSSBackend interface {
	Backend

	// GetPVSSState gets the PVSS beacon round state for the
	// provided block height.  Calling this method with height
	// `consensus.HeightLatest` should return the beacon for
	// the latest finalized block.
	GetPVSSState(context.Context, int64) (*PVSSState, error)

	// WatchLatestPVSSEvent returns a channel that produces a
	// stream of mesages on PVSS round events.  If a round
	// transition happens before the previous round event is read
	// from the channel, old events are overwritten.
	//
	// Upon subscription the current round event is sent immediately.
	WatchLatestPVSSEvent(ctx context.Context) (<-chan *PVSSEvent, *pubsub.Subscription, error)
}
