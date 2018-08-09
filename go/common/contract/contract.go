// Package contract implements common contract routines.
package contract

import (
	"encoding/hex"
	"errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/grpc/common"

	"github.com/ugorji/go/codec"
)

var (
	// ErrMalformedStoreID is the error returned when a storage service
	// ID is malformed.
	ErrMalformedStoreID = errors.New("contract: Malformed store ID")

	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("node: Protobuf is nil")
)

// StoreID is a storage service ID.
// TODO: Move this to the storage package when it exists.
type StoreID [32]byte

// MarshalBinary encodes a StoreID into binary form.
func (id *StoreID) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, id[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled StoreID.
func (id *StoreID) UnmarshalBinary(data []byte) error {
	const idSize = 32

	if len(data) != idSize {
		return ErrMalformedStoreID
	}

	copy(id[:], data)
	return nil
}

// String returns a string representation of a StoreID.
func (id *StoreID) String() string {
	return hex.EncodeToString(id[:])
}

// Contract represents a contract (aka runtime).
type Contract struct {
	// ID is a globally unique long term identifier of the contract.
	ID signature.PublicKey

	// StoreID is the storage service ID associated with the contract.
	StoreID StoreID

	// Code is the contract code body.
	Code []byte

	// MinimumBond is the mimimum stake required by the contract.
	MinimumBond uint64

	// ModeNonDeterministic indicates if the contract should be executed
	// in a non-deterministic manner.
	ModeNonDeterministic bool

	// FeaturesSGX indicates if the contract requires SGX.
	FeaturesSGX bool

	// AdvertisementRate is the number of tokens/second of contract
	// instance advertisement.
	AdvertisementRate uint64

	// ReplicaGroupSize is the size of the computation group.
	ReplicaGroupSize uint64

	// ReplicaGroupBackupSize is the size of the discrepancy resolution
	// replica group.
	ReplicaGroupBackupSize uint64

	// ReplicaAllowedStragglers is the number of allowed stragglers.
	ReplicaAllowedStragglers uint64

	// StorageGroupSize is the size of the storage group.
	StorageGroupSize uint64
}

// FromProto deserializes a protobuf into a Contract.
func (c *Contract) FromProto(pb *common.Contract) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	if c.ID == nil {
		c.ID = signature.PublicKey{}
	}

	if err := c.ID.UnmarshalBinary(pb.GetId()); err != nil {
		return err
	}

	if err := c.StoreID.UnmarshalBinary(pb.GetStoreId()); err != nil {
		return err
	}

	c.Code = append([]byte{}, pb.GetCode()...)
	c.MinimumBond = pb.GetMinimumBond()
	c.AdvertisementRate = pb.GetAdvertisementRate()
	c.ReplicaGroupSize = pb.GetReplicaGroupSize()
	c.ReplicaGroupBackupSize = pb.GetReplicaGroupBackupSize()
	c.ReplicaAllowedStragglers = pb.GetReplicaAllowedStragglers()
	c.StorageGroupSize = pb.GetStorageGroupSize()

	switch pb.GetMode() {
	case common.Contract_Nondeterministic:
		c.ModeNonDeterministic = true
	default:
		c.ModeNonDeterministic = false
	}

	c.FeaturesSGX = pbWantsSGX(pb)

	return nil
}

// ToProto serializes a Contract into a protobuf.
func (c *Contract) ToProto() *common.Contract {
	pb := new(common.Contract)
	var err error

	if pb.Id, err = c.ID.MarshalBinary(); err != nil {
		return nil
	}
	if pb.StoreId, err = c.StoreID.MarshalBinary(); err != nil {
		return nil
	}
	pb.Code = append([]byte{}, c.Code...)
	pb.MinimumBond = c.MinimumBond
	pb.AdvertisementRate = c.AdvertisementRate
	pb.ReplicaGroupSize = c.ReplicaGroupSize
	pb.ReplicaGroupBackupSize = c.ReplicaGroupBackupSize
	pb.ReplicaAllowedStragglers = c.ReplicaAllowedStragglers
	pb.StorageGroupSize = c.StorageGroupSize

	switch c.ModeNonDeterministic {
	case true:
		pb.Mode = common.Contract_Nondeterministic
	case false:
		pb.Mode = common.Contract_Deterministic
	}

	if c.FeaturesSGX {
		pb.Features = append([]common.Contract_Features{}, common.Contract_SGX)
	}

	return pb
}

// ToSignable serializes the Contract into a signature compatible byte vector.
func (c *Contract) ToSignable() []byte {
	var b []byte
	enc := codec.NewEncoderBytes(&b, signature.CBORHandle)
	if err := enc.Encode(c); err != nil {
		panic(err)
	}

	return b
}

func pbWantsSGX(pb *common.Contract) bool {
	for _, f := range pb.GetFeatures() {
		if f == common.Contract_SGX {
			return true
		}
	}

	return false
}
