// Package api defines the Oasis genesis block.
package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const filePerm = 0o600

// Document is a genesis document.
type Document struct {
	// Height is the block height at which the document was generated.
	Height int64 `json:"height"`
	// Time is the time the genesis block was constructed.
	Time time.Time `json:"genesis_time"`
	// ChainID is the ID of the chain.
	ChainID string `json:"chain_id"`
	// EpochTime is the timekeeping genesis state.
	EpochTime epochtime.Genesis `json:"epochtime"`
	// Registry is the registry genesis state.
	Registry registry.Genesis `json:"registry"`
	// RootHash is the roothash genesis state.
	RootHash roothash.Genesis `json:"roothash"`
	// Staking is the staking genesis state.
	Staking staking.Genesis `json:"staking"`
	// KeyManager is the key manager genesis state.
	KeyManager keymanager.Genesis `json:"keymanager"`
	// Scheduler is the scheduler genesis state.
	Scheduler scheduler.Genesis `json:"scheduler"`
	// Beacon is the beacon genesis state.
	Beacon beacon.Genesis `json:"beacon"`
	// Consensus is the consensus genesis state.
	Consensus consensus.Genesis `json:"consensus"`
	// HaltEpoch is the epoch height at which the network will stop processing
	// any transactions and will halt.
	HaltEpoch epochtime.EpochTime `json:"halt_epoch"`
	// Extra data is arbitrary extra data that is part of the
	// genesis block but is otherwise ignored by the protocol.
	ExtraData map[string][]byte `json:"extra_data"`
}

// Hash returns the cryptographic hash of the encoded genesis document.
func (d *Document) Hash() hash.Hash {
	return hash.NewFrom(d)
}

// ChainContext returns a string that can be used as a chain domain separation
// context. Changing this (or any data it is derived from) invalidates all
// signatures that use chain domain separation.
//
// Currently this uses the hex-encoded cryptographic hash of the encoded
// genesis document.
func (d *Document) ChainContext() string {
	return d.Hash().String()
}

// SetChainContext configures the global chain domain separation context.
//
// This method can only be called once during the application's lifetime and
// will panic otherwise.
func (d *Document) SetChainContext() {
	signature.SetChainContext(d.ChainContext())
}

// WriteFileJSON writes the genesis document into a JSON file.
func (d *Document) WriteFileJSON(filename string) error {
	docJSON, err := json.Marshal(d)
	if err != nil {
		return err
	}

	if err = ioutil.WriteFile(filename, docJSON, filePerm); err != nil {
		return fmt.Errorf("WriteFileJSON: failed to write genesis file: %w", err)
	}
	return nil
}

// Provider is a genesis document provider.
type Provider interface {
	// GetGenesisDocument returns the genesis document.
	GetGenesisDocument() (*Document, error)
}
