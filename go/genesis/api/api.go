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
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
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
	// Governance is the governance genesis state.
	Governance governance.Genesis `json:"governance"`
	// Consensus is the consensus genesis state.
	Consensus consensus.Genesis `json:"consensus"`
	// HaltEpoch is the epoch height at which the network will stop processing
	// any transactions and will halt.
	HaltEpoch beacon.EpochTime `json:"halt_epoch"`
	// Extra data is arbitrary extra data that is part of the
	// genesis block but is otherwise ignored by the protocol.
	ExtraData map[string][]byte `json:"extra_data"`

	cachedHash *hash.Hash
}

// Hash returns the cryptographic hash of the encoded genesis document.
//
// Calling this method will cause the computed hash to be cached so make sure
// that the document is not modified later.
func (d *Document) Hash() hash.Hash {
	if d.cachedHash != nil {
		return *d.cachedHash
	}
	h := hash.NewFrom(d)
	d.cachedHash = &h
	return h
}

// ChainContext returns a string that can be used as a chain domain separation
// context. Changing this (or any data it is derived from) invalidates all
// signatures that use chain domain separation.
//
// Currently this uses the hex-encoded cryptographic hash of the encoded
// genesis document.
func (d *Document) ChainContext() string {
	return d.Hash().Hex()
}

// SetChainContext configures the global chain domain separation context.
//
// This method can only be called once during the application's lifetime and
// will panic otherwise.
func (d *Document) SetChainContext() {
	signature.SetChainContext(d.ChainContext())
}

// CanonicalJSON returns the canonical form of the genesis document serialized
// into a file.
//
// This is a pretty-printed JSON file with 2-space indents following Go
// encoding/json package's JSON marshalling rules with a newline at the end.
func (d *Document) CanonicalJSON() ([]byte, error) {
	canonJSON, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return []byte{}, fmt.Errorf("CanonicalJSON: failed to marshal genesis document: %w", err)
	}
	// Append a newline at the end.
	canonJSON = append(canonJSON, []byte("\n")...)
	return canonJSON, nil
}

// WriteFileJSON writes the canonical form of genesis document into a file.
func (d *Document) WriteFileJSON(filename string) error {
	canonJSON, err := d.CanonicalJSON()
	if err != nil {
		return err
	}

	if err = ioutil.WriteFile(filename, canonJSON, filePerm); err != nil {
		return fmt.Errorf("WriteFileJSON: failed to write genesis file: %w", err)
	}
	return nil
}

// Provider is a genesis document provider.
type Provider interface {
	// GetGenesisDocument returns the genesis document.
	GetGenesisDocument() (*Document, error)
}
