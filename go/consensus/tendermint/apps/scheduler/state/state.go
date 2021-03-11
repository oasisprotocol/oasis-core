package state

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	"github.com/oasisprotocol/oasis-core/go/scheduler/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var (
	// committeeKeyFmt is the key format used for committees.
	//
	// Value is CBOR-serialized committee.
	committeeKeyFmt = keyformat.New(0x60, uint8(0), keyformat.H(&common.Namespace{}))
	// validatorsCurrentKeyFmt is the key format used for the current set of
	// validators.
	//
	// Value is CBOR-serialized map of validator public keys to voting power.
	validatorsCurrentKeyFmt = keyformat.New(0x61)
	// validatorsPendingKeyFmt is the key format used for the pending set of
	// validators.
	//
	// Value is CBOR-serialized map of validator public keys to voting power.
	validatorsPendingKeyFmt = keyformat.New(0x62)
	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Value is CBOR-serialized api.ConsensusParameters.
	parametersKeyFmt = keyformat.New(0x63)
)

// ImmutableState is the immutable scheduler state wrapper.
type ImmutableState struct {
	is *abciAPI.ImmutableState
}

// Committee returns a specific elected committee.
func (s *ImmutableState) Committee(ctx context.Context, kind api.CommitteeKind, runtimeID common.Namespace) (*api.Committee, error) {
	raw, err := s.is.Get(ctx, committeeKeyFmt.Encode(uint8(kind), &runtimeID))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, nil
	}

	var committee *api.Committee
	if err = cbor.Unmarshal(raw, &committee); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return committee, nil
}

// AllCommittees returns a list of all elected committees.
func (s *ImmutableState) AllCommittees(ctx context.Context) ([]*api.Committee, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var committees []*api.Committee
	for it.Seek(committeeKeyFmt.Encode()); it.Valid(); it.Next() {
		var k uint8
		var hRuntimeID keyformat.PreHashed
		if !committeeKeyFmt.Decode(it.Key(), &k, &hRuntimeID) {
			break
		}

		var c api.Committee
		if err := cbor.Unmarshal(it.Value(), &c); err != nil {
			err = fmt.Errorf("malformed committee %s (kind %d): %w", hRuntimeID, k, err)
			return nil, abciAPI.UnavailableStateError(err)
		}

		committees = append(committees, &c)
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	return committees, nil
}

// KindsCommittees returns a list of all committees of specific kinds.
func (s *ImmutableState) KindsCommittees(ctx context.Context, kinds []api.CommitteeKind) ([]*api.Committee, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var committees []*api.Committee
	for _, kind := range kinds {
		for it.Seek(committeeKeyFmt.Encode(uint8(kind))); it.Valid(); it.Next() {
			var k uint8
			var hRuntimeID keyformat.PreHashed
			if !committeeKeyFmt.Decode(it.Key(), &k, &hRuntimeID) || k != uint8(kind) {
				break
			}

			var c api.Committee
			if err := cbor.Unmarshal(it.Value(), &c); err != nil {
				err = fmt.Errorf("malformed committee %s (kind %d): %w", hRuntimeID, k, err)
				return nil, abciAPI.UnavailableStateError(err)
			}

			committees = append(committees, &c)
		}
		if it.Err() != nil {
			return nil, abciAPI.UnavailableStateError(it.Err())
		}
	}
	return committees, nil
}

// CurrentValidators returns a list of current validators.
func (s *ImmutableState) CurrentValidators(ctx context.Context) (map[signature.PublicKey]int64, error) {
	raw, err := s.is.Get(ctx, validatorsCurrentKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, nil
	}

	var validators map[signature.PublicKey]int64
	if err = cbor.Unmarshal(raw, &validators); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return validators, nil
}

// PendingValidators returns a list of pending validators.
func (s *ImmutableState) PendingValidators(ctx context.Context) (map[signature.PublicKey]int64, error) {
	raw, err := s.is.Get(ctx, validatorsPendingKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, nil
	}

	var validators map[signature.PublicKey]int64
	if err = cbor.Unmarshal(raw, &validators); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return validators, nil
}

// ConsensusParameters returns scheduler consensus parameters.
func (s *ImmutableState) ConsensusParameters(ctx context.Context) (*api.ConsensusParameters, error) {
	raw, err := s.is.Get(ctx, parametersKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, fmt.Errorf("tendermint/scheduler: expected consensus parameters to be present in app state")
	}

	var params api.ConsensusParameters
	if err = cbor.Unmarshal(raw, &params); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &params, nil
}

func NewImmutableState(ctx context.Context, state abciAPI.ApplicationQueryState, version int64) (*ImmutableState, error) {
	is, err := abciAPI.NewImmutableState(ctx, state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{is}, nil
}

// MutableState is a mutable scheduler state wrapper.
type MutableState struct {
	*ImmutableState

	ms mkvs.KeyValueTree
}

// PutCommittee sets an elected committee for a specific runtime.
func (s *MutableState) PutCommittee(ctx context.Context, c *api.Committee) error {
	err := s.ms.Insert(ctx, committeeKeyFmt.Encode(uint8(c.Kind), &c.RuntimeID), cbor.Marshal(c))
	return abciAPI.UnavailableStateError(err)
}

// DropCommittee removes an elected committee of a specific kind for a specific runtime.
func (s *MutableState) DropCommittee(ctx context.Context, kind api.CommitteeKind, runtimeID common.Namespace) error {
	err := s.ms.Remove(ctx, committeeKeyFmt.Encode(uint8(kind), &runtimeID))
	return abciAPI.UnavailableStateError(err)
}

// PutCurrentValidators stores the current set of validators.
func (s *MutableState) PutCurrentValidators(ctx context.Context, validators map[signature.PublicKey]int64) error {
	err := s.ms.Insert(ctx, validatorsCurrentKeyFmt.Encode(), cbor.Marshal(validators))
	return abciAPI.UnavailableStateError(err)
}

// PutPendingValidators stores the pending set of validators.
func (s *MutableState) PutPendingValidators(ctx context.Context, validators map[signature.PublicKey]int64) error {
	if validators == nil {
		err := s.ms.Remove(ctx, validatorsPendingKeyFmt.Encode())
		return abciAPI.UnavailableStateError(err)
	}
	err := s.ms.Insert(ctx, validatorsPendingKeyFmt.Encode(), cbor.Marshal(validators))
	return abciAPI.UnavailableStateError(err)
}

// SetConsensusParameters sets the scheduler consensus parameters.
//
// NOTE: This method must only be called from InitChain/EndBlock contexts.
func (s *MutableState) SetConsensusParameters(ctx context.Context, params *api.ConsensusParameters) error {
	if err := s.is.CheckContextMode(ctx, []abciAPI.ContextMode{abciAPI.ContextInitChain, abciAPI.ContextEndBlock}); err != nil {
		return err
	}
	err := s.ms.Insert(ctx, parametersKeyFmt.Encode(), cbor.Marshal(params))
	return abciAPI.UnavailableStateError(err)
}

// NewMutableState creates a new mutable scheduler state wrapper.
func NewMutableState(tree mkvs.KeyValueTree) *MutableState {
	return &MutableState{
		ImmutableState: &ImmutableState{
			&abciAPI.ImmutableState{ImmutableKeyValueTree: tree},
		},
		ms: tree,
	}
}
