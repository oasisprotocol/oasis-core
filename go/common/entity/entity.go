// Package entity implements common entity routines.
package entity

import (
	"errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/ethereum"
	"github.com/oasislabs/ekiden/go/grpc/common"

	"github.com/ugorji/go/codec"
)

// ErrNilProtobuf is the error returned when a protobuf is nil.
var ErrNilProtobuf = errors.New("entity: Protobuf is nil")

// Entity represents an entity that controls one or more Nodes and or
// services.
type Entity struct {
	// ID is the public key identifying the entity.
	ID signature.PublicKey

	// EthAddress is the Ethereum address of this Entity.
	EthAddress *ethereum.Address
}

// FromProto deserializes a protobuf into an Entity.
func (e *Entity) FromProto(pb *common.Entity) error {
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

	return nil
}

// ToProto serializes the Entity into a protobuf.
func (e *Entity) ToProto() *common.Entity {
	pb := new(common.Entity)

	pb.Id, _ = e.ID.MarshalBinary()
	if e.EthAddress != nil {
		pb.EthAddress, _ = e.EthAddress.MarshalBinary()
	}

	return pb
}

// ToSignable serializes the Entity into a signature compatible byte vector.
func (e *Entity) ToSignable() []byte {
	var b []byte
	enc := codec.NewEncoderBytes(&b, signature.CBORHandle)
	if err := enc.Encode(e); err != nil {
		panic(err)
	}

	return b
}
