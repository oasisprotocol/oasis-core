package state

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

var (
	// statusKeyFmt is the key manager status key format.
	//
	// Value is CBOR-serialized key manager status.
	statusKeyFmt = keyformat.New(0x70, keyformat.H(&common.Namespace{}))
	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Value is CBOR-serialized keymanager.ConsensusParameters.
	parametersKeyFmt = keyformat.New(0x71)
	// ephemeralSecretKeyFmt is the key manager ephemeral secret key format.
	//
	// Value is CBOR-serialized key manager signed encrypted ephemeral secret.
	ephemeralSecretKeyFmt = keyformat.New(0x72, keyformat.H(&common.Namespace{}), uint64(0))
)

// ImmutableState is the immutable key manager state wrapper.
type ImmutableState struct {
	is *abciAPI.ImmutableState
}

// ConsensusParameters returns the key manager consensus parameters.
func (st *ImmutableState) ConsensusParameters(ctx context.Context) (*api.ConsensusParameters, error) {
	raw, err := st.is.Get(ctx, parametersKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, fmt.Errorf("cometbft/keymanager: expected consensus parameters to be present in app state")
	}

	var params api.ConsensusParameters
	if err = cbor.Unmarshal(raw, &params); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &params, nil
}

func (st *ImmutableState) Statuses(ctx context.Context) ([]*api.Status, error) {
	rawStatuses, err := st.getStatusesRaw(ctx)
	if err != nil {
		return nil, err
	}

	var statuses []*api.Status
	for _, raw := range rawStatuses {
		var status api.Status
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

func (st *ImmutableState) Status(ctx context.Context, id common.Namespace) (*api.Status, error) {
	data, err := st.is.Get(ctx, statusKeyFmt.Encode(&id))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, api.ErrNoSuchStatus
	}

	var status api.Status
	if err := cbor.Unmarshal(data, &status); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &status, nil
}

func (st *ImmutableState) EphemeralSecret(ctx context.Context, id common.Namespace, epoch beacon.EpochTime) (*api.SignedEncryptedEphemeralSecret, error) {
	data, err := st.is.Get(ctx, ephemeralSecretKeyFmt.Encode(&id, uint64(epoch)))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, api.ErrNoSuchEphemeralSecret
	}

	var secret api.SignedEncryptedEphemeralSecret
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
func (st *MutableState) SetConsensusParameters(ctx context.Context, params *api.ConsensusParameters) error {
	if err := st.is.CheckContextMode(ctx, []abciAPI.ContextMode{abciAPI.ContextInitChain, abciAPI.ContextEndBlock}); err != nil {
		return err
	}
	err := st.ms.Insert(ctx, parametersKeyFmt.Encode(), cbor.Marshal(params))
	return abciAPI.UnavailableStateError(err)
}

func (st *MutableState) SetStatus(ctx context.Context, status *api.Status) error {
	err := st.ms.Insert(ctx, statusKeyFmt.Encode(&status.ID), cbor.Marshal(status))
	return abciAPI.UnavailableStateError(err)
}

func (st *MutableState) SetEphemeralSecret(ctx context.Context, secret *api.SignedEncryptedEphemeralSecret) error {
	err := st.ms.Insert(ctx, ephemeralSecretKeyFmt.Encode(&secret.Secret.ID, uint64(secret.Secret.Epoch)), cbor.Marshal(secret))
	return abciAPI.UnavailableStateError(err)
}

// CleanEphemeralSecrets removes all ephemeral secrets before the given epoch.
func (st *MutableState) CleanEphemeralSecrets(ctx context.Context, id common.Namespace, epoch beacon.EpochTime) error {
	it := st.is.NewIterator(ctx)
	defer it.Close()

	hID := keyformat.PreHashed(id.Hash())

	var toDelete []node.Key
	for it.Seek(ephemeralSecretKeyFmt.Encode(&id)); it.Valid(); it.Next() {
		var esID keyformat.PreHashed
		var esEpoch beacon.EpochTime
		if !ephemeralSecretKeyFmt.Decode(it.Key(), &esID, (*uint64)(&esEpoch)) {
			break
		}
		if hID != esID || esEpoch >= epoch {
			break
		}
		toDelete = append(toDelete, it.Key())
	}
	if it.Err() != nil {
		return abciAPI.UnavailableStateError(it.Err())
	}
	for _, key := range toDelete {
		if err := st.ms.Remove(ctx, key); err != nil {
			return abciAPI.UnavailableStateError(err)
		}
	}
	return nil
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
