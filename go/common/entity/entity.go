// Package entity implements common entity routines.
package entity

import (
	"errors"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/ethereum"
	pbCommon "github.com/oasislabs/ekiden/go/grpc/common"
)

var (
	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("entity: Protobuf is nil")

	_ cbor.Marshaler   = (*Entity)(nil)
	_ cbor.Unmarshaler = (*Entity)(nil)
)

// Entity represents an entity that controls one or more Nodes and or
// services.
type Entity struct {
	// ID is the public key identifying the entity.
	ID signature.PublicKey `codec:"id"`

	// EthAddress is the Ethereum address of this Entity.
	EthAddress *ethereum.Address `codec:"eth_address"`

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

	if b := pb.GetEthAddress(); b != nil {
		e.EthAddress = new(ethereum.Address)
		if err := e.EthAddress.UnmarshalBinary(b); err != nil {
			return err
		}
	}

	e.RegistrationTime = pb.GetRegistrationTime()

	return nil
}

// ToProto serializes the Entity into a protobuf.
func (e *Entity) ToProto() *pbCommon.Entity {
	pb := new(pbCommon.Entity)

	pb.Id, _ = e.ID.MarshalBinary()
	if e.EthAddress != nil {
		pb.EthAddress, _ = e.EthAddress.MarshalBinary()
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

// SignedEntity is a signed blob containing a CBOR-serialized Entity.
type SignedEntity struct {
	signature.Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedEntity) Open(context []byte, entity *Entity) error { // nolint: interfacer
	return s.Signed.Open(context, entity)
}

// SignEntity serializes the Entity and signs the result.
func SignEntity(privateKey signature.PrivateKey, context []byte, entity *Entity) (*SignedEntity, error) {
	signed, err := signature.SignSigned(privateKey, context, entity)
	if err != nil {
		return nil, err
	}

	return &SignedEntity{
		Signed: *signed,
	}, nil
}
