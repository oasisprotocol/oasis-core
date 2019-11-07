package state

import (
	"github.com/tendermint/iavl"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/keymanager/api"
)

var (
	// statusKeyFmt is the key manager status key format.
	//
	// Value is CBOR-serialized key manager status.
	statusKeyFmt = keyformat.New(0x70, &signature.MapKey{})
)

type ImmutableState struct {
	*abci.ImmutableState
}

func (st *ImmutableState) Statuses() ([]*api.Status, error) {
	rawStatuses, err := st.getStatusesRaw()
	if err != nil {
		return nil, err
	}

	var statuses []*api.Status
	for _, raw := range rawStatuses {
		var status api.Status
		if err = cbor.Unmarshal(raw, &status); err != nil {
			return nil, err
		}
		statuses = append(statuses, &status)
	}

	return statuses, nil
}

func (st *ImmutableState) getStatusesRaw() ([][]byte, error) {
	var rawVec [][]byte
	st.Snapshot.IterateRange(
		statusKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			if !statusKeyFmt.Decode(key) {
				return true
			}
			rawVec = append(rawVec, value)
			return false
		},
	)

	return rawVec, nil
}

func (st *ImmutableState) Status(id signature.PublicKey) (*api.Status, error) {
	_, raw := st.Snapshot.Get(statusKeyFmt.Encode(&id))
	if raw == nil {
		return nil, nil
	}

	var status api.Status
	if err := cbor.Unmarshal(raw, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func NewImmutableState(state *abci.ApplicationState, version int64) (*ImmutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}
	return &ImmutableState{inner}, nil
}

// MutableState is a mutable key manager state wrapper.
type MutableState struct {
	*ImmutableState

	tree *iavl.MutableTree
}

func (st *MutableState) SetStatus(status *api.Status) {
	st.tree.Set(statusKeyFmt.Encode(&status.ID), cbor.Marshal(status))
}

// NewMutableState creates a new mutable key manager state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		ImmutableState: &ImmutableState{inner},
		tree:           tree,
	}
}
