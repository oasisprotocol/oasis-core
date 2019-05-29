package scheduler

import (
	"fmt"

	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

const (
	statePoison       = "scheduler/poison"
	stateCommitteeMap = "scheduler/committee/%s/%s"
)

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) isPoisoned() bool {
	_, value := s.Snapshot.Get([]byte(statePoison))
	return value != nil
}

func (s *immutableState) getCommittee(kind api.CommitteeKind, runtimeID signature.PublicKey) ([]*api.CommitteeNode, error) {
	_, raw := s.Snapshot.Get([]byte(fmt.Sprintf(stateCommitteeMap, kind, runtimeID.String())))
	if raw == nil {
		return nil, nil
	}

	var members []*api.CommitteeNode
	err := cbor.Unmarshal(raw, &members)
	return members, err
}

func newImmutableState(state *abci.ApplicationState, version int64) (*immutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &immutableState{inner}, nil
}

type mutableState struct {
	*immutableState

	tree *iavl.MutableTree
}

func (s *mutableState) poison() {
	s.tree.Set(
		[]byte(statePoison),
		[]byte{1},
	)
}

func (s *mutableState) putCommittee(kind api.CommitteeKind, runtimeID signature.PublicKey, members []*api.CommitteeNode) {
	s.tree.Set(
		[]byte(fmt.Sprintf(stateCommitteeMap, kind, runtimeID.String())),
		cbor.Marshal(members),
	)
}

func newMutableState(tree *iavl.MutableTree) *mutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &mutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
