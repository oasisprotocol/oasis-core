package scheduler

import (
	"fmt"

	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

const (
	stateCommitteeMap = "scheduler/committee/%02x/%s"

	stateCurrentValidators = "scheduler/validators/current"
	statePendingValidators = "scheduler/validators/pending"
)

var logger = logging.GetLogger("tendermint/scheduler")

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) GetCommittee(kind api.CommitteeKind, runtimeID signature.PublicKey) (*api.Committee, error) {
	_, raw := s.Snapshot.Get([]byte(fmt.Sprintf(stateCommitteeMap, uint8(kind), runtimeID)))
	if raw == nil {
		return nil, nil
	}

	var committee *api.Committee
	err := cbor.Unmarshal(raw, &committee)
	return committee, err
}

func (s *immutableState) getAllCommittees() ([]*api.Committee, error) {
	var committees []*api.Committee
	s.Snapshot.IterateRange(
		[]byte(fmt.Sprintf(stateCommitteeMap, 0, abci.FirstID)),
		[]byte(fmt.Sprintf(stateCommitteeMap, uint8(api.MaxCommitteeKind), abci.FirstID)),
		true,
		func(key, value []byte) bool {
			var c *api.Committee
			err := cbor.Unmarshal(value, &c)
			if err != nil {
				logger.Error("couldn't get committee from state entry",
					"key", key,
					"value", value,
					"err", err,
				)
				return false
			}
			committees = append(committees, c)
			return false
		},
	)
	return committees, nil
}

func (s *immutableState) getKindsCommittees(kinds []api.CommitteeKind) ([]*api.Committee, error) {
	var committees []*api.Committee
	for _, kind := range kinds {
		s.Snapshot.IterateRangeInclusive(
			[]byte(fmt.Sprintf(stateCommitteeMap, uint8(kind), abci.FirstID)),
			[]byte(fmt.Sprintf(stateCommitteeMap, uint8(kind), abci.LastID)),
			true,
			func(key, value []byte, version int64) bool {
				var c *api.Committee
				err := cbor.Unmarshal(value, &c)
				if err != nil {
					logger.Error("couldn't get committee from state entry",
						"key", key,
						"value", value,
						"err", err,
					)
					return false
				}
				committees = append(committees, c)
				return false
			},
		)
	}
	return committees, nil
}

func (s *immutableState) getCurrentValidators() ([]signature.PublicKey, error) {
	_, raw := s.Snapshot.Get([]byte(stateCurrentValidators))
	if raw == nil {
		return nil, nil
	}

	var validators []signature.PublicKey
	err := cbor.Unmarshal(raw, &validators)
	return validators, err
}

func (s *immutableState) getPendingValidators() ([]signature.PublicKey, error) {
	_, raw := s.Snapshot.Get([]byte(statePendingValidators))
	if raw == nil {
		return nil, nil
	}

	var validators []signature.PublicKey
	err := cbor.Unmarshal(raw, &validators)
	return validators, err
}

func newImmutableState(state *abci.ApplicationState, version int64) (*immutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &immutableState{inner}, nil
}

// MutableState is a mutable scheduler state wrapper.
type MutableState struct {
	*immutableState

	tree *iavl.MutableTree
}

func (s *MutableState) putCommittee(c *api.Committee) {
	s.tree.Set(
		[]byte(fmt.Sprintf(stateCommitteeMap, uint8(c.Kind), c.RuntimeID)),
		cbor.Marshal(c),
	)
}

func (s *MutableState) dropCommittee(kind api.CommitteeKind, runtimeID signature.PublicKey) {
	s.tree.Remove([]byte(fmt.Sprintf(stateCommitteeMap, uint8(kind), runtimeID)))
}

func (s *MutableState) putCurrentValidators(validators []signature.PublicKey) {
	s.tree.Set([]byte(stateCurrentValidators), cbor.Marshal(validators))
}

func (s *MutableState) putPendingValidators(validators []signature.PublicKey) {
	if validators == nil {
		s.tree.Remove([]byte(statePendingValidators))
		return
	}
	s.tree.Set([]byte(statePendingValidators), cbor.Marshal(validators))
}

// NewMutableState creates a new mutable scheduler state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
