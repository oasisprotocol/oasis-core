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
)

var (
	logger = logging.GetLogger("tendermint/scheduler")
)

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) GetCommittee(kind api.CommitteeKind, runtimeID signature.PublicKey) ([]*api.CommitteeNode, error) {
	_, raw := s.Snapshot.Get([]byte(fmt.Sprintf(stateCommitteeMap, uint8(kind), runtimeID)))
	if raw == nil {
		return nil, nil
	}

	var members []*api.CommitteeNode
	err := cbor.Unmarshal(raw, &members)
	return members, err
}

func committeeFromEntry(key, value []byte) (*api.Committee, error) {
	var (
		runtimeIDHex string
		kind         api.CommitteeKind
	)
	n, err := fmt.Sscanf(string(key), stateCommitteeMap, &kind, &runtimeIDHex)
	if err != nil {
		return nil, fmt.Errorf("couldn't scan committee key: %s", err.Error())
	}
	if n < 2 {
		return nil, fmt.Errorf("only scanned %d parts", n)
	}
	var runtimeID signature.PublicKey
	if err := runtimeID.UnmarshalHex(runtimeIDHex); err != nil {
		return nil, fmt.Errorf("couldn't unmarshal committee runtime ID: %s", err.Error())
	}
	var members []*api.CommitteeNode
	if err := cbor.Unmarshal(value, &members); err != nil {
		return nil, fmt.Errorf("couldn't unmarshal committee value: %s", err.Error())
	}
	return &api.Committee{
		RuntimeID: runtimeID,
		Kind:      kind,
		Members:   members,
	}, nil
}

func (s *immutableState) getAllCommittees() ([]*api.Committee, error) {
	var committees []*api.Committee
	s.Snapshot.IterateRange(
		[]byte(fmt.Sprintf(stateCommitteeMap, 0, abci.FirstID)),
		[]byte(fmt.Sprintf(stateCommitteeMap, uint8(api.MaxCommitteeKind), abci.FirstID)),
		true,
		func(key, value []byte) bool {
			c, err := committeeFromEntry(key, value)
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
				c, err := committeeFromEntry(key, value)
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

func (s *MutableState) putCommittee(kind api.CommitteeKind, runtimeID signature.PublicKey, members []*api.CommitteeNode) {
	s.tree.Set(
		[]byte(fmt.Sprintf(stateCommitteeMap, uint8(kind), runtimeID)),
		cbor.Marshal(members),
	)
}

func (s *MutableState) dropCommittee(kind api.CommitteeKind, runtimeID signature.PublicKey) {
	s.tree.Remove([]byte(fmt.Sprintf(stateCommitteeMap, uint8(kind), runtimeID)))
}

// NewMutableState creates a new mutable scheduler state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
