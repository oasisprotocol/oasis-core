package abci

import (
	"errors"

	"github.com/tendermint/iavl"
)

var (
	// ErrNoState is the error returned when state is nil.
	ErrNoState = errors.New("tendermint: no state available (app not registered?)")
	// ErrNoCommittedBlocks is the error returned when there are no committed
	// blocks and as such no state can be queried.
	ErrNoCommittedBlocks = errors.New("tendermint: no committed blocks")
)

// ImmutableState is an immutable state wrapper.
type ImmutableState struct {
	// Snapshot is the backing immutable iAVL tree snapshot.
	Snapshot *iavl.ImmutableTree
}

// NewImmutableState creates a new immutable state wrapper.
func NewImmutableState(state *ApplicationState, version int64) (*ImmutableState, error) {
	if state == nil {
		return nil, ErrNoState
	}
	if state.BlockHeight() == 0 {
		return nil, ErrNoCommittedBlocks
	}
	if version <= 0 || version > state.BlockHeight() {
		version = state.BlockHeight()
	}

	snapshot, err := state.DeliverTxTree().GetImmutable(version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{Snapshot: snapshot}, nil
}
