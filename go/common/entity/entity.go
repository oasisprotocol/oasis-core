// Package entity implements common entity routines.
package entity

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	pbCommon "github.com/oasislabs/oasis-core/go/grpc/common"
)

const (
	entityFilename = "entity.json"

	fileMode = 0600
)

var (
	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("entity: Protobuf is nil")

	_ cbor.Marshaler   = (*Entity)(nil)
	_ cbor.Unmarshaler = (*Entity)(nil)

	testEntity       Entity
	testEntitySigner signature.Signer
)

// Entity represents an entity that controls one or more Nodes and or
// services.
type Entity struct {
	// ID is the public key identifying the entity.
	ID signature.PublicKey `json:"id"`

	// Nodes is the vector of node identity keys owned by this entity, that
	// will sign the descriptor with the node signing key rather than the
	// entity signing key.
	Nodes []signature.PublicKey `json:"nodes"`

	// Time of registration.
	RegistrationTime uint64 `json:"registration_time"`

	// AllowEntitySignedNodes is true iff nodes belonging to this entity
	// may be signed with the entity signing key.
	AllowEntitySignedNodes bool `json:"allow_entity_signed_nodes"`
}

// String returns a string representation of itself.
func (e *Entity) String() string {
	return "<Entity id=" + e.ID.String() + ">"
}

// FromProto deserializes a protobuf into an Entity.
func (e *Entity) FromProto(pb *pbCommon.Entity) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	if err := e.ID.UnmarshalBinary(pb.GetId()); err != nil {
		return err
	}

	e.Nodes = nil
	for _, v := range pb.GetNodes() {
		var nodeID signature.PublicKey
		if err := nodeID.UnmarshalBinary(v); err != nil {
			return err
		}
		e.Nodes = append(e.Nodes, nodeID)
	}

	e.RegistrationTime = pb.GetRegistrationTime()
	e.AllowEntitySignedNodes = pb.GetAllowEntitySignedNodes()

	return nil
}

// ToProto serializes the Entity into a protobuf.
func (e *Entity) ToProto() *pbCommon.Entity {
	pb := new(pbCommon.Entity)

	pb.Id, _ = e.ID.MarshalBinary()
	pb.RegistrationTime = e.RegistrationTime
	pb.AllowEntitySignedNodes = e.AllowEntitySignedNodes

	var pbNodes [][]byte
	for _, v := range e.Nodes {
		rawNodeID, _ := v.MarshalBinary()
		pbNodes = append(pbNodes, rawNodeID)
	}
	pb.Nodes = pbNodes

	return pb
}

// ToSignable serializes the Entity into a signature compatible byte vector.
func (e *Entity) ToSignable() []byte {
	return e.MarshalCBOR()
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (e *Entity) MarshalCBOR() []byte {
	return cbor.Marshal(e)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (e *Entity) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, e)
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
func Load(baseDir string, signerFactory signature.SignerFactory) (*Entity, signature.Signer, error) {
	entityPath := filepath.Join(baseDir, entityFilename)

	// Load the entity signer.
	signer, err := signerFactory.Load(signature.SignerEntity)
	if err != nil {
		return nil, nil, err
	}

	ent, err := LoadDescriptor(entityPath)
	if err != nil {
		signer.Reset()
		return nil, nil, err
	}

	return ent, signer, nil
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

// Generate generates a new entity and serializes it to disk.
func Generate(baseDir string, signerFactory signature.SignerFactory, template *Entity) (*Entity, signature.Signer, error) {
	// Generate a new entity.
	signer, err := signerFactory.Generate(signature.SignerEntity, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ent := &Entity{
		ID:               signer.Public(),
		RegistrationTime: uint64(time.Now().Unix()),
	}
	if template != nil {
		ent.Nodes = template.Nodes
		ent.AllowEntitySignedNodes = template.AllowEntitySignedNodes
	}

	if err = ent.Save(baseDir); err != nil {
		return nil, nil, err
	}

	return ent, signer, nil
}

// TestEntity returns the built-in test entity and signer.
func TestEntity() (*Entity, signature.Signer, error) {
	return &testEntity, testEntitySigner, nil
}

// SignedEntity is a signed blob containing a CBOR-serialized Entity.
type SignedEntity struct {
	signature.Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedEntity) Open(context []byte, entity *Entity) error { // nolint: interfacer
	return s.Signed.Open(context, entity)
}

// SignEntity serializes the Entity and signs the result.
func SignEntity(signer signature.Signer, context []byte, entity *Entity) (*SignedEntity, error) {
	signed, err := signature.SignSigned(signer, context, entity)
	if err != nil {
		return nil, err
	}

	return &SignedEntity{
		Signed: *signed,
	}, nil
}

func init() {
	testEntitySigner = memorySigner.NewTestSigner("ekiden test entity key seed")

	testEntity.ID = testEntitySigner.Public()
	testEntity.RegistrationTime = uint64(time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC).Unix())
	testEntity.AllowEntitySignedNodes = true
}
