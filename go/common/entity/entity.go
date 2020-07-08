// Package entity implements common entity routines.
package entity

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/multisig"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	entityFilename = "entity.json"

	fileMode = 0o600
)

var (
	testEntity        Entity
	testEntitySigner  signature.Signer
	testEntityAccount *multisig.Account

	_ prettyprint.PrettyPrinter = (*SignedEntity)(nil)
)

const (
	// LatestEntityDescriptorVersion is the latest entity descriptor version that should be used for
	// all new descriptors. Using earlier versions may be rejected.
	LatestEntityDescriptorVersion = 1

	// Minimum and maximum descriptor versions that are allowed.
	minEntityDescriptorVersion = 1
	maxEntityDescriptorVersion = LatestEntityDescriptorVersion
)

// Entity represents an entity that controls one or more Nodes and or
// services.
type Entity struct { // nolint: maligned
	cbor.Versioned

	// AccountAddress is the account address identifying the entity.
	AccountAddress staking.Address `json:"account_address"`

	// Nodes is the vector of node identity keys owned by this entity, that
	// will sign the descriptor with the node signing key rather than the
	// entity signing key.
	Nodes []signature.PublicKey `json:"nodes,omitempty"`

	// AllowEntitySignedNodes is true iff nodes belonging to this entity
	// may be signed with the entity signing key.
	AllowEntitySignedNodes bool `json:"allow_entity_signed_nodes,omitempty"`
}

// ValidateBasic performs basic descriptor validity checks.
func (e *Entity) ValidateBasic(strictVersion bool) error {
	switch strictVersion {
	case true:
		// Only the latest version is allowed.
		if e.Versioned.V != LatestEntityDescriptorVersion {
			return fmt.Errorf("invalid entity descriptor version (expected: %d got: %d)",
				LatestEntityDescriptorVersion,
				e.Versioned.V,
			)
		}
	case false:
		// A range of versions is allowed.
		if e.Versioned.V < minEntityDescriptorVersion || e.Versioned.V > maxEntityDescriptorVersion {
			return fmt.Errorf("invalid entity descriptor version (min: %d max: %d)",
				minEntityDescriptorVersion,
				maxEntityDescriptorVersion,
			)
		}
	}
	return nil
}

// String returns a string representation of itself.
func (e Entity) String() string {
	return "<Entity address=" + e.AccountAddress.String() + ">"
}

// Save saves the JSON serialized entity descriptor.
func (e *Entity) Save(baseDir string) error {
	entityPath := filepath.Join(baseDir, entityFilename)

	// Write to disk.
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(entityPath, b, fileMode)
}

// Load loads an existing entity from disk.
func Load(baseDir string, signerFactory signature.SignerFactory) (*Entity, signature.Signer, *multisig.Account, error) {
	entityPath := filepath.Join(baseDir, entityFilename)

	// Load the entity signer.
	signer, err := signerFactory.Load(signature.SignerEntity)
	if err != nil {
		return nil, nil, nil, err
	}

	ent, err := LoadDescriptor(entityPath)
	if err != nil {
		signer.Reset()
		return nil, nil, nil, err
	}

	signerAccount := multisig.NewAccountFromPublicKey(signer.Public())
	signerAccountAddr := staking.NewAddress(signerAccount)

	if !ent.AccountAddress.Equal(signerAccountAddr) {
		signer.Reset()
		return nil, nil, nil, fmt.Errorf("account mismatch (signer: %s, entity: %s)", signerAccountAddr, ent.AccountAddress)
	}

	return ent, signer, signerAccount, nil
}

// LoadDescriptor loads an existing entity from disk, without loading the signer.
// Note: This takes the path to the descriptor rather than a base directory.
func LoadDescriptor(f string) (*Entity, error) {
	rawEnt, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}

	var ent Entity
	if err = json.Unmarshal(rawEnt, &ent); err != nil {
		return nil, err
	}

	return &ent, nil
}

// GenerateWithSigner generates a new entity using an existing signer and serializes it to disk.
func GenerateWithSigner(baseDir string, signer signature.Signer, template *Entity) (*Entity, *multisig.Account, error) {
	// Generate a new entity.
	account := multisig.NewAccountFromPublicKey(signer.Public())
	ent := &Entity{
		Versioned: cbor.Versioned{
			V: LatestEntityDescriptorVersion,
		},
		AccountAddress: staking.NewAddress(account),
	}
	if template != nil {
		ent.Nodes = template.Nodes
		ent.AllowEntitySignedNodes = template.AllowEntitySignedNodes
	}

	if err := ent.Save(baseDir); err != nil {
		return nil, nil, err
	}
	return ent, account, nil
}

// Generate generates a new entity and serializes it to disk.
func Generate(baseDir string, signerFactory signature.SignerFactory, template *Entity) (*Entity, signature.Signer, *multisig.Account, error) {
	// Generate a new entity.
	signer, err := signerFactory.Generate(signature.SignerEntity, rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	ent, account, err := GenerateWithSigner(baseDir, signer, template)
	if err != nil {
		return nil, nil, nil, err
	}
	return ent, signer, account, nil
}

// TestEntity returns the built-in test entity and signer.
func TestEntity() (*Entity, signature.Signer, *multisig.Account, error) {
	return &testEntity, testEntitySigner, testEntityAccount, nil
}

// SignedEntity is a signed blob containing a CBOR-serialized Entity.
type SignedEntity struct {
	multisig.Envelope
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedEntity) Open(context signature.Context, entity *Entity) error { // nolint: interfacer
	return s.Envelope.Open(context, entity)
}

// PrettyPrint writes a pretty-printed representation of the type
// to the given writer.
func (s SignedEntity) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	pt, err := s.PrettyType()
	if err != nil {
		fmt.Fprintf(w, "%s<error: %s>\n", prefix, err)
		return
	}

	pt.(prettyprint.PrettyPrinter).PrettyPrint(ctx, prefix, w)
}

// PrettyType returns a representation of the type that can be used for pretty printing.
func (s SignedEntity) PrettyType() (interface{}, error) {
	var e Entity
	if err := cbor.Unmarshal(s.Envelope.Payload, &e); err != nil {
		return nil, fmt.Errorf("malformed signed payload: %w", err)
	}
	return multisig.NewPrettyEnvelope(s.Envelope, e)
}

// SingleSignEntity serializes the Entity and signs the result.
//
// Note: This is a convenience routine that does not support entities
// backed by accounts with more than 1 signer.
func SingleSignEntity(signer signature.Signer, account *multisig.Account, context signature.Context, entity *Entity) (*SignedEntity, error) {
	if len(account.Signers) != 1 {
		return nil, fmt.Errorf("attemtped to single-sign multi-sig entity")
	}
	rawEntity := cbor.Marshal(entity)
	entitySig, err := multisig.Sign(signer, account, context, rawEntity)
	if err != nil {
		return nil, err
	}
	envelope, err := multisig.NewEnvelope(account, []*signature.Signature{entitySig}, rawEntity)
	if err != nil {
		return nil, err
	}
	return &SignedEntity{*envelope}, nil
}

func init() {
	testEntitySigner = memorySigner.NewTestSigner("ekiden test entity key seed")

	testEntityAccount = multisig.NewAccountFromPublicKey(testEntitySigner.Public())

	testEntity.Versioned.V = LatestEntityDescriptorVersion
	testEntity.AccountAddress = staking.NewAddress(testEntityAccount)
	testEntity.AllowEntitySignedNodes = true
}
