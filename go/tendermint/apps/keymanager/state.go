package keymanager

import (
	"fmt"

	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/keymanager/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

const stateStatusMap = "keymanager/status/%s"

var ()

type immutableState struct {
	*abci.ImmutableState
}

func (st *immutableState) GetStatuses() ([]*api.Status, error) {
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

func (st *immutableState) getStatusesRaw() ([][]byte, error) {
	var rawVec [][]byte
	st.Snapshot.IterateRangeInclusive(
		[]byte(fmt.Sprintf(stateStatusMap, "")),
		[]byte(fmt.Sprintf(stateStatusMap, abci.LastID)),
		true,
		func(key, value []byte, version int64) bool {
			rawVec = append(rawVec, value)
			return false
		},
	)

	return rawVec, nil
}

func (st *immutableState) GetStatus(id signature.PublicKey) (*api.Status, error) {
	_, raw := st.Snapshot.Get([]byte(fmt.Sprintf(stateStatusMap, id.String())))
	if raw == nil {
		return nil, nil
	}

	var status api.Status
	if err := cbor.Unmarshal(raw, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func newImmutableState(state *abci.ApplicationState, version int64) (*immutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}
	return &immutableState{inner}, nil
}

// MutableState is a mutable key manager state wrapper.
type MutableState struct {
	*immutableState

	tree *iavl.MutableTree
}

func (st *MutableState) setStatus(status *api.Status) {
	st.tree.Set([]byte(fmt.Sprintf(stateStatusMap, status.ID.String())), cbor.Marshal(status))
}

// NewMutableState creates a new mutable key manager state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
