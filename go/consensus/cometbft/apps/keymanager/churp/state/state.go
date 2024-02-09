package state

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var (
	// parametersKeyFmt is the consensus parameters key format.
	//
	// Value is CBOR-serialized churp.ConsensusParameters.
	parametersKeyFmt = consensus.KeyFormat.New(0x74)

	// statusKeyFmt is the status key format.
	//
	// Key format is: 0x75 <runtime-id> <churp-id>.
	// Value is CBOR-serialized churp.Status.
	statusKeyFmt = consensus.KeyFormat.New(0x75, keyformat.H(&common.Namespace{}), uint8(0))
)

// ImmutableState is a immutable state wrapper.
type ImmutableState struct {
	is *abciAPI.ImmutableState
}

// ConsensusParameters returns the consensus parameters.
func (st *ImmutableState) ConsensusParameters(ctx context.Context) (*churp.ConsensusParameters, error) {
	raw, err := st.is.Get(ctx, parametersKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, fmt.Errorf("cometbft/keymanager/churp: expected consensus parameters to be present in app state")
	}

	var params churp.ConsensusParameters
	if err = cbor.Unmarshal(raw, &params); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &params, nil
}

// Status returns the CHURP status for the specified runtime and CHURP instance.
func (st *ImmutableState) Status(ctx context.Context, runtimeID common.Namespace, churpID uint8) (*churp.Status, error) {
	data, err := st.is.Get(ctx, statusKeyFmt.Encode(&runtimeID, churpID))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, churp.ErrNoSuchStatus
	}

	var status churp.Status
	if err := cbor.Unmarshal(data, &status); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &status, nil
}

// Statuses returns the CHURP statuses for the specified runtime.
func (st *ImmutableState) Statuses(ctx context.Context, runtimeID common.Namespace) ([]*churp.Status, error) {
	it := st.is.NewIterator(ctx)
	defer it.Close()

	// We need to pre-hash the runtime ID, so we can compare it below.
	runtimeIDHash := keyformat.PreHashed(runtimeID.Hash())

	var statuses []*churp.Status
	for it.Seek(statusKeyFmt.Encode(&runtimeID)); it.Valid(); it.Next() {
		var (
			hash    keyformat.PreHashed
			churpID uint8
		)
		if !statusKeyFmt.Decode(it.Key(), &hash, &churpID) {
			break
		}
		if runtimeIDHash != hash {
			break
		}

		var status churp.Status
		if err := cbor.Unmarshal(it.Value(), &status); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}
		statuses = append(statuses, &status)
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}

	return statuses, nil
}

// AllStatuses returns the CHURP statuses for all runtimes.
func (st *ImmutableState) AllStatuses(ctx context.Context) ([]*churp.Status, error) {
	it := st.is.NewIterator(ctx)
	defer it.Close()

	var statuses []*churp.Status
	for it.Seek(statusKeyFmt.Encode()); it.Valid(); it.Next() {
		if !statusKeyFmt.Decode(it.Key()) {
			break
		}

		var status churp.Status
		if err := cbor.Unmarshal(it.Value(), &status); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}
		statuses = append(statuses, &status)
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}

	return statuses, nil
}

// NewImmutableState creates a new immutable state wrapper.
func NewImmutableState(ctx context.Context, state abciAPI.ApplicationQueryState, version int64) (*ImmutableState, error) {
	is, err := abciAPI.NewImmutableState(ctx, state, version)
	if err != nil {
		return nil, err
	}
	return &ImmutableState{is}, nil
}

// MutableState is a mutable state wrapper.
type MutableState struct {
	*ImmutableState

	ms mkvs.KeyValueTree
}

// SetConsensusParameters updates the state using the provided consensus parameters.
//
// This method must only be called from InitChain or EndBlock contexts.
func (st *MutableState) SetConsensusParameters(ctx context.Context, params *churp.ConsensusParameters) error {
	if err := st.is.CheckContextMode(ctx, []abciAPI.ContextMode{abciAPI.ContextInitChain, abciAPI.ContextEndBlock}); err != nil {
		return err
	}
	err := st.ms.Insert(ctx, parametersKeyFmt.Encode(), cbor.Marshal(params))
	return abciAPI.UnavailableStateError(err)
}

// SetStatus updates the state using the provided CHURP status.
func (st *MutableState) SetStatus(ctx context.Context, status *churp.Status) error {
	err := st.ms.Insert(ctx, statusKeyFmt.Encode(&status.RuntimeID, status.ID), cbor.Marshal(status))
	return abciAPI.UnavailableStateError(err)
}

// NewMutableState creates a new mutable state wrapper.
func NewMutableState(tree mkvs.KeyValueTree) *MutableState {
	return &MutableState{
		ImmutableState: &ImmutableState{
			&abciAPI.ImmutableState{ImmutableKeyValueTree: tree},
		},
		ms: tree,
	}
}
