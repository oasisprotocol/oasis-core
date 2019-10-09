package scheduler

import (
	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/keyformat"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

var (
	// committeeKeyFmt is the key format used for committees.
	//
	// Value is CBOR-serialized committee.
	committeeKeyFmt = keyformat.New(0x60, uint8(0), &signature.MapKey{})
	// validatorsCurrentKeyFmt is the key format used for the current set of
	// validators.
	//
	// Value is CBOR-serialized list of validator public keys.
	validatorsCurrentKeyFmt = keyformat.New(0x61)
	// validatorsPendingKeyFmt is the key format used for the pending set of
	// validators.
	//
	// Value is CBOR-serialized list of validator public keys.
	validatorsPendingKeyFmt = keyformat.New(0x62)

	logger = logging.GetLogger("tendermint/scheduler")
)

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) GetCommittee(kind api.CommitteeKind, runtimeID signature.PublicKey) (*api.Committee, error) {
	_, raw := s.Snapshot.Get(committeeKeyFmt.Encode(uint8(kind), &runtimeID))
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
		committeeKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			if !committeeKeyFmt.Decode(key) {
				return true
			}

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
		s.Snapshot.IterateRange(
			committeeKeyFmt.Encode(uint8(kind)),
			nil,
			true,
			func(key, value []byte) bool {
				var k uint8
				if !committeeKeyFmt.Decode(key, &k) || k != uint8(kind) {
					return true
				}

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
	_, raw := s.Snapshot.Get(validatorsCurrentKeyFmt.Encode())
	if raw == nil {
		return nil, nil
	}

	var validators []signature.PublicKey
	err := cbor.Unmarshal(raw, &validators)
	return validators, err
}

func (s *immutableState) getPendingValidators() ([]signature.PublicKey, error) {
	_, raw := s.Snapshot.Get(validatorsPendingKeyFmt.Encode())
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
	s.tree.Set(committeeKeyFmt.Encode(uint8(c.Kind), &c.RuntimeID), cbor.Marshal(c))
}

func (s *MutableState) dropCommittee(kind api.CommitteeKind, runtimeID signature.PublicKey) {
	s.tree.Remove(committeeKeyFmt.Encode(uint8(kind), &runtimeID))
}

func (s *MutableState) putCurrentValidators(validators []signature.PublicKey) {
	s.tree.Set(validatorsCurrentKeyFmt.Encode(), cbor.Marshal(validators))
}

func (s *MutableState) putPendingValidators(validators []signature.PublicKey) {
	if validators == nil {
		s.tree.Remove(validatorsPendingKeyFmt.Encode())
		return
	}
	s.tree.Set(validatorsPendingKeyFmt.Encode(), cbor.Marshal(validators))
}

// NewMutableState creates a new mutable scheduler state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
