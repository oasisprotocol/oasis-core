package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
)

// GasOpVRFProve is the gas operation identifier for VRF proof submission.
const GasOpVRFProve transaction.Op = "vrf_prove"

var (
	// MethodVRFProve is the method name for a VRF proof.
	MethodVRFProve = transaction.NewMethodName(ModuleName, "VRFProve", VRFProve{})

	// DefaultVRFGasCosts are the default gas costs for VRF operations.
	DefaultVRFGasCosts = transaction.Costs{
		GasOpVRFProve: 1000,
	}
)

// VRFParameters are the beacon parameters for the VRF backend.
type VRFParameters struct {
	// AlphaHighQualityThreshold is the minimum number of proofs (Pi)
	// that must be received for the next input (Alpha) to be considered
	// high quality.  If the VRF input is not high quality, runtimes will
	// be disabled for the next epoch.
	AlphaHighQualityThreshold uint64 `json:"alpha_hq_threshold,omitempty"`

	// Interval is the epoch interval (in blocks).
	Interval int64 `json:"interval,omitempty"`

	// ProofSubmissionDelay is the wait peroid in blocks after an epoch
	// transition that nodes MUST wait before attempting to submit a
	// VRF proof for the next epoch's elections.
	ProofSubmissionDelay int64 `json:"proof_delay,omitempty"`

	// GasCosts are the VRF proof gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`
}

// VRFState is the VRF backend state.
type VRFState struct {
	// Epoch is the epoch for which this alpha is valid.
	Epoch EpochTime `json:"epoch,omitempty"`

	// Alpha is the active VRF alpha_string input.
	Alpha []byte `json:"alpha,omitempty"`

	// Pi is the accumulated pi_string (VRF proof) outputs.
	Pi map[signature.PublicKey]*signature.Proof `json:"pi,omitempty"`

	// AlphaIsHighQuality is true iff the alpha was generated from
	// high quality input such that elections will be possible.
	AlphaIsHighQuality bool `json:"alpha_hq,omitempty"`

	// SubmitAfter is the block height after which nodes may submit
	// VRF proofs for the current epoch.
	SubmitAfter int64 `json:"submit_after,omitempty"`

	// PrevState is the VRF state from the previous epoch, for the
	// current epoch's elections.
	PrevState *PrevVRFState `json:"prev_state,omitempty"`
}

// PrevVRFState is the previous epoch's VRF state that is to be used for
// elections.
type PrevVRFState struct {
	// Pi is the accumulated pi_string (VRF proof) outputs for the
	// previous epoch.
	Pi map[signature.PublicKey]*signature.Proof `json:"pi.omitempty"`

	// CanElectCommittees is true iff the previous alpha was generated
	// from high quality input such that committee elections are possible.
	CanElectCommittees bool `json:"can_elect,omitempty"`
}

// VRFProve is a VRF proof transaction payload.
type VRFProve struct {
	Epoch EpochTime `json:"epoch"`

	Pi []byte `json:"pi"`
}

// VRFEvent is a VRF backend event.
type VRFEvent struct {
	// Epoch is the epoch that Alpha is valid for.
	Epoch EpochTime `json:"epoch,omitempty"`

	// Alpha is the active VRF alpha_string input.
	Alpha []byte `json:"alpha,omitempty"`

	// SubmitAfter is the block height after which nodes may submit
	// VRF proofs for the current epoch.
	SubmitAfter int64 `json:"submit_after"`
}

func (ev *VRFEvent) FromState(state *VRFState) {
	ev.Epoch = state.Epoch
	ev.Alpha = state.Alpha
	ev.SubmitAfter = state.SubmitAfter
}

// EventKind returns a string representation of this event's kind.
func (ev *VRFEvent) EventKind() string {
	return "vrf"
}

// VRFBackend is a Backend that is backed by VRFs.
type VRFBackend interface {
	Backend

	// GetVRFState gets the VRF state for the provided block height.
	GetVRFState(context.Context, int64) (*VRFState, error)

	// WatchLatestVRFEvent returns a channel that produces a stream
	// of messages on VRF events.  If an epoch transition happens
	// before the previous epoch event is read from the channel, old
	// events are overwritten.
	//
	// Upon subscription the current epoch event is sent immediately.
	WatchLatestVRFEvent(ctx context.Context) (<-chan *VRFEvent, *pubsub.Subscription, error)
}
