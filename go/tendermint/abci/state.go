package abci

import "github.com/tendermint/iavl"

// FirstID is the lowest hex-encoded node/entity/runtime/etc identifier.
const FirstID = "0000000000000000000000000000000000000000000000000000000000000000"

// LastID is the highest hex-encoded node/entity/runtime/etc identifier.
const LastID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

// ImmutableState is an immutable state wrapper.
type ImmutableState struct {
	// Snapshot is the backing immutable iAVL tree snapshot.
	Snapshot *iavl.ImmutableTree
}

// NewImmutableState creates a new immutable state wrapper.
func NewImmutableState(state *ApplicationState, version int64) (*ImmutableState, error) {
	if version <= 0 || version > state.BlockHeight() {
		version = state.BlockHeight()
	}

	snapshot, err := state.DeliverTxTree().GetImmutable(version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{Snapshot: snapshot}, nil
}
