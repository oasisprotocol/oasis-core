package state

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var (
	// statusKeyFmt is the key manager status key format.
	//
	// Value is CBOR-serialized key manager status.
	statusKeyFmt = consensus.KeyFormat.New(0x70, keyformat.H(&common.Namespace{}))
	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Value is CBOR-serialized keymanager.ConsensusParameters.
	parametersKeyFmt = consensus.KeyFormat.New(0x71)
	// masterSecretKeyFmt is the key manager master secret key format.
	//
	// Value is CBOR-serialized key manager signed encrypted master secret.
	masterSecretKeyFmt = consensus.KeyFormat.New(0x72, keyformat.H(&common.Namespace{}))
	// ephemeralSecretKeyFmt is the key manager ephemeral secret key format.
	//
	// Value is CBOR-serialized key manager signed encrypted ephemeral secret.
	ephemeralSecretKeyFmt = consensus.KeyFormat.New(0x73, keyformat.H(&common.Namespace{}))
)

// ImmutableState is the immutable key manager state wrapper.
type ImmutableState struct {
	is *abciAPI.ImmutableState
}

// ConsensusParameters returns the key manager consensus parameters.
func (st *ImmutableState) ConsensusParameters(ctx context.Context) (*secrets.ConsensusParameters, error) {
	raw, err := st.is.Get(ctx, parametersKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, fmt.Errorf("cometbft/keymanager: expected consensus parameters to be present in app state")
	}

	var params secrets.ConsensusParameters
	if err = cbor.Unmarshal(raw, &params); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &params, nil
}

func (st *ImmutableState) Statuses(ctx context.Context) ([]*secrets.Status, error) {
	rawStatuses, err := st.getStatusesRaw(ctx)
	if err != nil {
		return nil, err
	}

	var statuses []*secrets.Status
	for _, raw := range rawStatuses {
		var status secrets.Status
		if err = cbor.Unmarshal(raw, &status); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}
		statuses = append(statuses, &status)
	}

	return statuses, nil
}

func (st *ImmutableState) getStatusesRaw(ctx context.Context) ([][]byte, error) {
	it := st.is.NewIterator(ctx)
	defer it.Close()

	var rawVec [][]byte
	for it.Seek(statusKeyFmt.Encode()); it.Valid(); it.Next() {
		if !statusKeyFmt.Decode(it.Key()) {
			break
		}
		rawVec = append(rawVec, it.Value())
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	return rawVec, nil
}

func (st *ImmutableState) Status(ctx context.Context, id common.Namespace) (*secrets.Status, error) {
	data, err := st.is.Get(ctx, statusKeyFmt.Encode(&id))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, secrets.ErrNoSuchStatus
	}

	var status secrets.Status
	if err := cbor.Unmarshal(data, &status); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &status, nil
}

func (st *ImmutableState) MasterSecret(ctx context.Context, id common.Namespace) (*secrets.SignedEncryptedMasterSecret, error) {
	data, err := st.is.Get(ctx, masterSecretKeyFmt.Encode(&id))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, secrets.ErrNoSuchMasterSecret
	}

	var secret secrets.SignedEncryptedMasterSecret
	if err := cbor.Unmarshal(data, &secret); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &secret, nil
}

func (st *ImmutableState) EphemeralSecret(ctx context.Context, id common.Namespace) (*secrets.SignedEncryptedEphemeralSecret, error) {
	data, err := st.is.Get(ctx, ephemeralSecretKeyFmt.Encode(&id))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, secrets.ErrNoSuchEphemeralSecret
	}

	var secret secrets.SignedEncryptedEphemeralSecret
	if err := cbor.Unmarshal(data, &secret); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &secret, nil
}

func NewImmutableState(ctx context.Context, state abciAPI.ApplicationQueryState, version int64) (*ImmutableState, error) {
	is, err := abciAPI.NewImmutableState(ctx, state, version)
	if err != nil {
		return nil, err
	}
	return &ImmutableState{is}, nil
}

// MutableState is a mutable key manager state wrapper.
type MutableState struct {
	*ImmutableState

	ms mkvs.KeyValueTree
}

// SetConsensusParameters sets key manager consensus parameters.
//
// NOTE: This method must only be called from InitChain/EndBlock contexts.
func (st *MutableState) SetConsensusParameters(ctx context.Context, params *secrets.ConsensusParameters) error {
	if err := st.is.CheckContextMode(ctx, []abciAPI.ContextMode{abciAPI.ContextInitChain, abciAPI.ContextEndBlock}); err != nil {
		return err
	}
	err := st.ms.Insert(ctx, parametersKeyFmt.Encode(), cbor.Marshal(params))
	return abciAPI.UnavailableStateError(err)
}

func (st *MutableState) SetStatus(ctx context.Context, status *secrets.Status) error {
	err := st.ms.Insert(ctx, statusKeyFmt.Encode(&status.ID), cbor.Marshal(status))
	return abciAPI.UnavailableStateError(err)
}

func (st *MutableState) SetMasterSecret(ctx context.Context, secret *secrets.SignedEncryptedMasterSecret) error {
	err := st.ms.Insert(ctx, masterSecretKeyFmt.Encode(&secret.Secret.ID), cbor.Marshal(secret))
	return abciAPI.UnavailableStateError(err)
}

func (st *MutableState) SetEphemeralSecret(ctx context.Context, secret *secrets.SignedEncryptedEphemeralSecret) error {
	err := st.ms.Insert(ctx, ephemeralSecretKeyFmt.Encode(&secret.Secret.ID), cbor.Marshal(secret))
	return abciAPI.UnavailableStateError(err)
}

// NewMutableState creates a new mutable key manager state wrapper.
func NewMutableState(tree mkvs.KeyValueTree) *MutableState {
	return &MutableState{
		ImmutableState: &ImmutableState{
			&abciAPI.ImmutableState{ImmutableKeyValueTree: tree},
		},
		ms: tree,
	}
}
