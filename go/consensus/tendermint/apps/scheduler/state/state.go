package state

import (
	"errors"

	"github.com/tendermint/iavl"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/scheduler/api"
)

var (
	// committeeKeyFmt is the key format used for committees.
	//
	// Value is CBOR-serialized committee.
	committeeKeyFmt = keyformat.New(0x60, uint8(0), &common.Namespace{})
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
	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Value is CBOR-serialized api.ConsensusParameters.
	parametersKeyFmt = keyformat.New(0x63)

	logger = logging.GetLogger("tendermint/scheduler")
)

type ImmutableState struct {
	*abci.ImmutableState
}

func (s *ImmutableState) Committee(kind api.CommitteeKind, runtimeID common.Namespace) (*api.Committee, error) {
	_, raw := s.Snapshot.Get(committeeKeyFmt.Encode(uint8(kind), &runtimeID))
	if raw == nil {
		return nil, nil
	}

	var committee *api.Committee
	err := cbor.Unmarshal(raw, &committee)
	return committee, err
}

func (s *ImmutableState) AllCommittees() ([]*api.Committee, error) {
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

func (s *ImmutableState) KindsCommittees(kinds []api.CommitteeKind) ([]*api.Committee, error) {
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

func (s *ImmutableState) CurrentValidators() ([]signature.PublicKey, error) {
	_, raw := s.Snapshot.Get(validatorsCurrentKeyFmt.Encode())
	if raw == nil {
		return nil, nil
	}

	var validators []signature.PublicKey
	err := cbor.Unmarshal(raw, &validators)
	return validators, err
}

func (s *ImmutableState) PendingValidators() ([]signature.PublicKey, error) {
	_, raw := s.Snapshot.Get(validatorsPendingKeyFmt.Encode())
	if raw == nil {
		return nil, nil
	}

	var validators []signature.PublicKey
	err := cbor.Unmarshal(raw, &validators)
	return validators, err
}

func (s *ImmutableState) ConsensusParameters() (*api.ConsensusParameters, error) {
	_, raw := s.Snapshot.Get(parametersKeyFmt.Encode())
	if raw == nil {
		return nil, errors.New("tendermint/scheduler: expected consensus parameters to be present in app state")
	}

	var params api.ConsensusParameters
	err := cbor.Unmarshal(raw, &params)
	return &params, err
}

func NewImmutableState(state *abci.ApplicationState, version int64) (*ImmutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{inner}, nil
}

// MutableState is a mutable scheduler state wrapper.
type MutableState struct {
	*ImmutableState

	tree *iavl.MutableTree
}

func (s *MutableState) PutCommittee(c *api.Committee) {
	s.tree.Set(committeeKeyFmt.Encode(uint8(c.Kind), &c.RuntimeID), cbor.Marshal(c))
}

func (s *MutableState) DropCommittee(kind api.CommitteeKind, runtimeID common.Namespace) {
	s.tree.Remove(committeeKeyFmt.Encode(uint8(kind), &runtimeID))
}

func (s *MutableState) PutCurrentValidators(validators []signature.PublicKey) {
	s.tree.Set(validatorsCurrentKeyFmt.Encode(), cbor.Marshal(validators))
}

func (s *MutableState) PutPendingValidators(validators []signature.PublicKey) {
	if validators == nil {
		s.tree.Remove(validatorsPendingKeyFmt.Encode())
		return
	}
	s.tree.Set(validatorsPendingKeyFmt.Encode(), cbor.Marshal(validators))
}

func (s *MutableState) SetConsensusParameters(params *api.ConsensusParameters) {
	s.tree.Set(parametersKeyFmt.Encode(), cbor.Marshal(params))
}

// NewMutableState creates a new mutable scheduler state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		ImmutableState: &ImmutableState{inner},
		tree:           tree,
	}
}
