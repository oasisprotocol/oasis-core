// Package entity implements common entity routines.
package entity

import (
	"crypto/rand"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/ekiden/go/common/json"
	pbCommon "github.com/oasislabs/ekiden/go/grpc/common"
)

const (
	entityFilename  = "entity.json"
	privKeyFilename = "entity.pem"

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
	ID signature.PublicKey `codec:"id"`

	// Time of registration.
	RegistrationTime uint64 `codec:"registration_time"`
}

// String returns a string representation of itself.
func (e *Entity) String() string {
	return "<Entity id=" + e.ID.String() + ">"
}

// Clone returns a copy of itself.
func (e *Entity) Clone() common.Cloneable {
	entityCopy := *e
	return &entityCopy
}

// FromProto deserializes a protobuf into an Entity.
func (e *Entity) FromProto(pb *pbCommon.Entity) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	if err := e.ID.UnmarshalBinary(pb.GetId()); err != nil {
		return err
	}

	e.RegistrationTime = pb.GetRegistrationTime()

	return nil
}

// ToProto serializes the Entity into a protobuf.
func (e *Entity) ToProto() *pbCommon.Entity {
	pb := new(pbCommon.Entity)

	pb.Id, _ = e.ID.MarshalBinary()
	pb.RegistrationTime = e.RegistrationTime

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

// LoadOrGenerate loads or generates an entity (to/on disk).
func LoadOrGenerate(baseDir string, signerFactory signature.SignerFactory) (*Entity, signature.Signer, error) {
	ent, signer, err := Load(baseDir, signerFactory)
	if err != nil {
		if !os.IsNotExist(err) && err != signature.ErrNotExist {
			return nil, nil, err
		}
		ent, signer, err = Generate(baseDir, signerFactory)
	}
	return ent, signer, err
}

// Load loads an existing entity from disk.
func Load(baseDir string, signerFactory signature.SignerFactory) (*Entity, signature.Signer, error) {
	entityPath, privKeyPath := getPaths(baseDir)

	// Load the entity signer.
	if err := signerFactory.EnsureRole(signature.SignerEntity); err != nil {
		return nil, nil, err
	}
	signer, err := signerFactory.Load(privKeyPath)
	if err != nil {
		return nil, nil, err
	}

	rawEnt, err := ioutil.ReadFile(entityPath)
	if err != nil {
		return nil, nil, err
	}

	var ent Entity
	if err = json.Unmarshal(rawEnt, &ent); err != nil {
		return nil, nil, err
	}

	return &ent, signer, nil
}

// Generate generates a new entity and serializes it to disk.
func Generate(baseDir string, signerFactory signature.SignerFactory) (*Entity, signature.Signer, error) {
	entityPath, privKeyPath := getPaths(baseDir)

	// Generate a new entity.
	if err := signerFactory.EnsureRole(signature.SignerEntity); err != nil {
		return nil, nil, err
	}
	signer, err := signerFactory.Generate(privKeyPath, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ent := &Entity{
		ID:               signer.Public(),
		RegistrationTime: uint64(time.Now().Unix()),
	}

	// Write to disk.
	if err = ioutil.WriteFile(entityPath, json.Marshal(ent), fileMode); err != nil {
		return nil, nil, err
	}

	return ent, signer, nil
}

// TestEntity returns the built-in test entity and signer.
func TestEntity() (*Entity, signature.Signer, error) {
	return &testEntity, testEntitySigner, nil
}

func getPaths(baseDir string) (string, string) {
	return filepath.Join(baseDir, entityFilename), filepath.Join(baseDir, privKeyFilename)
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
}
