// Package entity implements common entity routines.
package entity

import (
	"crypto/rand"
	"errors"
	"fmt"
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
	entityFilename = "entity.json"

	fileMode = 0600
)

var (
	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("entity: Protobuf is nil")

	_ cbor.Marshaler   = (*Entity)(nil)
	_ cbor.Unmarshaler = (*Entity)(nil)

	testEntity           Entity
	testEntitySigner     signature.Signer
	testEntitySubSigners map[SubkeyRole]signature.Signer

	allSubkeyRoles = []SubkeyRole{
		SubkeyNodeRegistration,
	}
)

// SubkeyRole is the role for a given entity subkey.
type SubkeyRole int

const (
	SubkeyInvalid          SubkeyRole = 0
	SubkeyNodeRegistration SubkeyRole = 1
)

// String returns the string representation of the subkey role.
func (r SubkeyRole) String() string {
	switch r {
	case SubkeyNodeRegistration:
		return "node registration"
	default:
		return "[invalid subkey role]"
	}
}

// ToSignerRole converts the subkey role to a signature SignerRole.
func (r SubkeyRole) ToSignerRole() signature.SignerRole {
	switch r {
	case SubkeyNodeRegistration:
		return signature.SignerEntityNodeRegistration
	default:
		panic("BUG: subkey role has no corresponding signer role")
	}
}

// Entity represents an entity that controls one or more Nodes and or
// services.
type Entity struct {
	// ID is the public key identifying the entity.
	ID signature.PublicKey `codec:"id"`

	// Subkeys containts the subsidiary signing keys for the entity.
	Subkeys map[SubkeyRole]*signature.PublicKey `codec:"subkeys"`

	// Time of registration.
	RegistrationTime uint64 `codec:"registration_time"`
}

// String returns a string representation of itself.
func (e *Entity) String() string {
	return "<Entity id=" + e.ID.String() + ">"
}

// Clone returns a copy of itself.
func (e *Entity) Clone() common.Cloneable {
	entityCopy := &Entity{
		ID:               e.ID,
		Subkeys:          make(map[SubkeyRole]*signature.PublicKey),
		RegistrationTime: e.RegistrationTime,
	}
	for k, v := range e.Subkeys {
		entityCopy.Subkeys[k] = v
	}

	return entityCopy
}

// FromProto deserializes a protobuf into an Entity.
func (e *Entity) FromProto(pb *pbCommon.Entity) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	if err := e.ID.UnmarshalBinary(pb.GetId()); err != nil {
		return err
	}
	e.Subkeys = make(map[SubkeyRole]*signature.PublicKey)
	for k, v := range e.Subkeys {
		var subPublic signature.PublicKey
		if err := subPublic.UnmarshalBinary(*v); err != nil {
			return err
		}
		e.Subkeys[k] = &subPublic
	}
	e.RegistrationTime = pb.GetRegistrationTime()

	return nil
}

// ToProto serializes the Entity into a protobuf.
func (e *Entity) ToProto() *pbCommon.Entity {
	pb := new(pbCommon.Entity)

	pb.Id, _ = e.ID.MarshalBinary()
	pb.Subkeys = make(map[uint32][]byte)
	for k, v := range e.Subkeys {
		buf, _ := v.MarshalBinary()
		pb.Subkeys[uint32(k)] = buf
	}
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

// GetSubkey gets the specifed subkey.
func (e *Entity) GetSubkey(r SubkeyRole) signature.PublicKey {
	if e.Subkeys == nil {
		return nil
	}
	subkey, ok := e.Subkeys[r]
	if !ok {
		return nil
	}
	return *subkey
}

// LoadOrGenerate loads or generates an entity (to/on disk).
func LoadOrGenerate(baseDir string, signerFactory signature.SignerFactory) (*Entity, signature.Signer, map[SubkeyRole]signature.Signer, error) {
	ent, signer, subSigners, err := Load(baseDir, signerFactory)
	if err != nil {
		if !os.IsNotExist(err) && err != signature.ErrNotExist {
			return nil, nil, nil, err
		}
		ent, signer, subSigners, err = Generate(baseDir, signerFactory)
	}
	return ent, signer, subSigners, err
}

// Load loads an existing entity from disk.
func Load(baseDir string, signerFactory signature.SignerFactory) (*Entity, signature.Signer, map[SubkeyRole]signature.Signer, error) {
	entityPath := filepath.Join(baseDir, entityFilename)

	// Load the entity signer.
	subSigners := make(map[SubkeyRole]signature.Signer) // For cleanup.
	signer, err := signerFactory.Load(signature.SignerEntity)
	if err != nil {
		return nil, nil, nil, err
	}

	var ok bool
	defer func() {
		if !ok {
			signer.Reset()
			for _, v := range subSigners {
				v.Reset()
			}
		}
	}()

	// Load the subkey signers.
	for _, v := range allSubkeyRoles {
		var subSigner signature.Signer
		subSigner, err = signerFactory.Load(v.ToSignerRole())
		if err != nil {
			return nil, nil, nil, err
		}
		subSigners[v] = subSigner
	}

	rawEnt, err := ioutil.ReadFile(entityPath)
	if err != nil {
		return nil, nil, nil, err
	}

	var ent Entity
	if err = json.Unmarshal(rawEnt, &ent); err != nil {
		return nil, nil, nil, err
	}

	if err = ensureSubSignerConsistency(&ent, subSigners); err != nil {
		return nil, nil, nil, err
	}

	ok = true
	return &ent, signer, subSigners, nil
}

// Generate generates a new entity and serializes it to disk.
func Generate(baseDir string, signerFactory signature.SignerFactory) (*Entity, signature.Signer, map[SubkeyRole]signature.Signer, error) {
	entityPath := filepath.Join(baseDir, entityFilename)

	// Generate a new entity signing key.
	subSigners := make(map[SubkeyRole]signature.Signer) // For cleanup.
	signer, err := signerFactory.Generate(signature.SignerEntity, rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	var ok bool
	defer func() {
		if !ok {
			signer.Reset()
			for _, v := range subSigners {
				v.Reset()
			}
		}
	}()

	ent := &Entity{
		ID:               signer.Public(),
		Subkeys:          make(map[SubkeyRole]*signature.PublicKey),
		RegistrationTime: uint64(time.Now().Unix()),
	}

	// Generate the new entity subkeys.
	for _, v := range allSubkeyRoles {
		var subSigner signature.Signer
		subSigner, err = signerFactory.Generate(v.ToSignerRole(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		subPublic := subSigner.Public()
		ent.Subkeys[v] = &subPublic
		subSigners[v] = subSigner
	}

	if err = ensureSubSignerConsistency(ent, subSigners); err != nil {
		return nil, nil, nil, err
	}

	// Write to disk.
	if err = ioutil.WriteFile(entityPath, json.Marshal(ent), fileMode); err != nil {
		return nil, nil, nil, err
	}

	ok = true
	return ent, signer, subSigners, nil
}

// TestEntity returns the built-in test entity, signer, and subkey signers.
func TestEntity() (*Entity, signature.Signer, map[SubkeyRole]signature.Signer, error) {
	return &testEntity, testEntitySigner, testEntitySubSigners, nil
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

func ensureSubSignerConsistency(entity *Entity, subSigners map[SubkeyRole]signature.Signer) error {
	for _, v := range allSubkeyRoles {
		subPublic := entity.Subkeys[v]
		if subPublic == nil {
			return fmt.Errorf("entity: no '%v' public key", v)
		}

		subSigner := subSigners[v]
		if subSigner == nil {
			return fmt.Errorf("entity: no '%v' signer", v)
		}

		if !subPublic.Equal(subSigner.Public()) {
			return fmt.Errorf("entity: '%v' public key/signer mismatch", v)
		}
	}
	return nil
}

func init() {
	testEntitySigner = memorySigner.NewTestSigner("ekiden test entity key seed")
	testEntity.ID = testEntitySigner.Public()
	testEntity.RegistrationTime = uint64(time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC).Unix())

	// Deal with the test subkeys.
	testEntity.Subkeys = make(map[SubkeyRole]*signature.PublicKey)
	testEntitySubSigners = make(map[SubkeyRole]signature.Signer)

	for _, v := range allSubkeyRoles {
		signer := memorySigner.NewTestSigner("ekiden test entity " + v.String())
		subPublic := signer.Public()
		testEntity.Subkeys[v] = &subPublic
		testEntitySubSigners[v] = signer
	}
}
