// Package api defines the Ekiden genesis block.
package api

import (
	"time"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	keymanager "github.com/oasislabs/ekiden/go/keymanager/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	staking "github.com/oasislabs/ekiden/go/staking/api"
)

var (
	_ cbor.Marshaler   = (*Document)(nil)
	_ cbor.Unmarshaler = (*Document)(nil)
)

// Document is a genesis document.
type Document struct {
	// Time is the time the genesis block was constructed.
	Time time.Time `codec:"genesis_time"`
	// Registry is the registry genesis state.
	Registry registry.Genesis `codec:"registry"`
	// RootHash is the roothash genesis state.
	RootHash roothash.Genesis `codec:"roothash"`
	// Staking is the staking genesis state.
	Staking staking.Genesis `codec:"staking"`
	// KeyManager is the key manager genesis state.
	KeyManager keymanager.Genesis `codec:"keymanager"`
	// Validators is the list of validators at genesis.
	Validators []*Validator `codec:"validators"`
	// Extra data is arbitrary extra data that is part of the
	// genesis block but is otherwise ignored by Ekiden.
	ExtraData map[string][]byte `codec:"extra_data"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (d *Document) MarshalCBOR() []byte {
	return cbor.Marshal(d)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (d *Document) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, d)
}

// Validator is an ekiden validator.
type Validator struct {
	PubKey      signature.PublicKey `codec:"pub_key"`
	Name        string              `codec:"name"`
	Power       int64               `codec:"power"`
	CoreAddress string              `codec:"core_address"`
}

// Provider is a genesis document provider.
type Provider interface {
	// GetGenesisDocument returns the genesis document.
	GetGenesisDocument() (*Document, error)
}
