package api

import (
	"errors"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	pbRegistry "github.com/oasislabs/ekiden/go/grpc/registry"
)

var (
	// ErrMalformedStoreID is the error returned when a storage service
	// ID is malformed.
	ErrMalformedStoreID = errors.New("runtime: Malformed store ID")

	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("node: Protobuf is nil")

	_ cbor.Marshaler   = (*Runtime)(nil)
	_ cbor.Unmarshaler = (*Runtime)(nil)
)

// Runtime represents a runtime.
type Runtime struct {
	// ID is a globally unique long term identifier of the runtime.
	ID signature.PublicKey `codec:"id"`

	// Genesis is the runtime genesis information.
	Genesis RuntimeGenesis

	// Code is the runtime code body.
	Code []byte `codec:"code"`

	// TEEHardware specifies the runtime's TEE hardware requirements.
	TEEHardware node.TEEHardware `codec:"tee_hardware"`

	// ReplicaGroupSize is the size of the computation group.
	ReplicaGroupSize uint64 `codec:"replica_group_size"`

	// ReplicaGroupBackupSize is the size of the discrepancy resolution
	// replica group.
	ReplicaGroupBackupSize uint64 `codec:"replica_group_backup_size"`

	// ReplicaAllowedStragglers is the number of allowed stragglers.
	ReplicaAllowedStragglers uint64 `codec:"replica_allowed_stragglers"`

	// StorageGroupSize is the size of the storage group.
	StorageGroupSize uint64 `codec:"storage_group_size"`

	// StorageGroupSize is the time of registration of the runtime.
	RegistrationTime uint64 `codec:"registration_time"`

	// TransactionSchedulerGroupSize the size of the TransactionScheduler group.
	TransactionSchedulerGroupSize uint64 `codec:"transaction_scheduler_group_size"`
}

// String returns a string representation of itself.
func (c *Runtime) String() string {
	return "<Runtime id=" + c.ID.String() + ">"
}

// Clone returns a copy of itself.
func (c *Runtime) Clone() common.Cloneable {
	runtimeCopy := *c
	return &runtimeCopy
}

// FromProto deserializes a protobuf into a Runtime.
func (c *Runtime) FromProto(pb *pbRegistry.Runtime) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	if c.ID == nil {
		c.ID = signature.PublicKey{}
	}

	if err := c.ID.UnmarshalBinary(pb.GetId()); err != nil {
		return err
	}

	c.Code = append([]byte{}, pb.GetCode()...)
	if err := c.TEEHardware.FromProto(pb.GetTeeHardware()); err != nil {
		return err
	}
	c.ReplicaGroupSize = pb.GetReplicaGroupSize()
	c.ReplicaGroupBackupSize = pb.GetReplicaGroupBackupSize()
	c.ReplicaAllowedStragglers = pb.GetReplicaAllowedStragglers()
	c.StorageGroupSize = pb.GetStorageGroupSize()
	c.RegistrationTime = pb.GetRegistrationTime()

	return nil
}

// ToProto serializes a Runtime into a protobuf.
func (c *Runtime) ToProto() *pbRegistry.Runtime {
	pb := new(pbRegistry.Runtime)
	var err error

	if pb.Id, err = c.ID.MarshalBinary(); err != nil {
		panic(err)
	}
	pb.Code = append([]byte{}, c.Code...)
	if pb.TeeHardware, err = c.TEEHardware.ToProto(); err != nil {
		panic(err)
	}
	pb.ReplicaGroupSize = c.ReplicaGroupSize
	pb.ReplicaGroupBackupSize = c.ReplicaGroupBackupSize
	pb.ReplicaAllowedStragglers = c.ReplicaAllowedStragglers
	pb.StorageGroupSize = c.StorageGroupSize
	pb.RegistrationTime = c.RegistrationTime

	return pb
}

// ToSignable serializes the Runtime into a signature compatible byte vector.
func (c *Runtime) ToSignable() []byte {
	return c.MarshalCBOR()
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (c *Runtime) MarshalCBOR() []byte {
	return cbor.Marshal(c)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (c *Runtime) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, c)
}

// SignedRuntime is a signed blob containing a CBOR-serialized Runtime.
type SignedRuntime struct {
	signature.Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedRuntime) Open(context []byte, runtime *Runtime) error { // nolint: interfacer
	return s.Signed.Open(context, runtime)
}

// SignRuntime serializes the Runtime and signs the result.
func SignRuntime(privateKey signature.PrivateKey, context []byte, runtime *Runtime) (*SignedRuntime, error) {
	signed, err := signature.SignSigned(privateKey, context, runtime)
	if err != nil {
		return nil, err
	}

	return &SignedRuntime{
		Signed: *signed,
	}, nil
}

// RuntimeGenesis is the runtime genesis information that is used to
// initialize runtime state in the first block.
type RuntimeGenesis struct {
	// StateRoot is the state root that should be used at genesis time. If
	// the runtime should start with empty state, this must be set to the
	// empty hash.
	StateRoot hash.Hash `codec:"state_root"`

	// StorageReceipt is the storage receipt for the state root.
	StorageReceipt signature.Signature `codec:"storage_receipt"`
}
