package state

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

// statusKeyFmt is the key manager status key format.
//
// Value is CBOR-serialized key manager status.
var statusKeyFmt = keyformat.New(0x70, keyformat.H(&common.Namespace{}))

// ImmutableState is the immutable key manager state wrapper.
type ImmutableState struct {
	is *abciAPI.ImmutableState
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

func (st *MutableState) SetStatus(ctx context.Context, status *api.Status) error {
	err := st.ms.Insert(ctx, statusKeyFmt.Encode(&status.ID), cbor.Marshal(status))
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
