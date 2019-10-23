package state

import (
	"errors"
	"fmt"

	"github.com/tendermint/iavl"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
)

var (
	// beaconKeyFmt is the random beacon key format.
	//
	// Value is raw random beacon.
	beaconKeyFmt = keyformat.New(0x40)
	// genesisKeyFmt is the key format used for genesis.
	genesisKeyFmt = keyformat.New(0x41)
)

type ImmutableState struct {
	*abci.ImmutableState
}

func NewImmutableState(state *abci.ApplicationState, version int64) (*ImmutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{inner}, nil
}

// Beacon gets the current random beacon value.
func (s *ImmutableState) Beacon() ([]byte, error) {
	_, b := s.Snapshot.Get(beaconKeyFmt.Encode())
	if b == nil {
		return nil, beacon.ErrBeaconNotAvailable
	}

	return b, nil
}

func (s *ImmutableState) GetGenesis() (*beacon.Genesis, error) {
	_, raw := s.Snapshot.Get(genesisKeyFmt.Encode())
	if raw == nil {
		panic(errors.New("tendermint/beacon: expected genesis to be present in app state"))
	}

	var genesis beacon.Genesis
	err := cbor.Unmarshal(raw, &genesis)
	return &genesis, err
}

// MutableState is a mutable beacon state wrapper.
type MutableState struct {
	*ImmutableState

	tree *iavl.MutableTree
}

func (s *MutableState) SetBeacon(newBeacon []byte) error {
	if l := len(newBeacon); l != beacon.BeaconSize {
		return fmt.Errorf("tendermint/beacon: unexpected beacon size: %d", l)
	}

	s.tree.Set(beaconKeyFmt.Encode(), newBeacon)

	return nil
}

func (s *MutableState) PutGenesis(g *beacon.Genesis) {
	s.tree.Set(genesisKeyFmt.Encode(), cbor.Marshal(g))
}

// NewMutableState creates a new mutable beacon state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		ImmutableState: &ImmutableState{inner},
		tree:           tree,
	}
}
