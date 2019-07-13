package api

import (
	"errors"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	pbRegistry "github.com/oasislabs/ekiden/go/grpc/registry"
	storage "github.com/oasislabs/ekiden/go/storage/api"
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

// RuntimeKind represents the runtime funtionality.
type RuntimeKind uint32

const (
	// KindCompute is a generic compute runtime.
	KindCompute RuntimeKind = 0

	// KindKeyManager is a key manager runtime.
	KindKeyManager RuntimeKind = 1
)

// Runtime represents a runtime.
type Runtime struct {
	// ID is a globally unique long term identifier of the runtime.
	ID signature.PublicKey `codec:"id"`

	// Genesis is the runtime genesis information.
	Genesis RuntimeGenesis `codec:"genesis"`

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

	// Kind is the type of runtime.
	Kind RuntimeKind `codec:"kind"`

	// TEEHardware specifies the runtime's TEE hardware requirements.
	TEEHardware node.TEEHardware `codec:"tee_hardware"`

	// KeyManager is the key manager runtime ID for this runtime.
	KeyManager signature.PublicKey `codec:"key_manager"`
}

// String returns a string representation of itself.
func (c *Runtime) String() string {
	return "<Runtime id=" + c.ID.String() + ">"
}

// IsCompute returns true iff the runtime is a generic compute runtime.
func (c *Runtime) IsCompute() bool {
	return c.Kind == KindCompute
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

	if err := c.TEEHardware.FromProto(pb.GetTeeHardware()); err != nil {
		return err
	}

	if err := c.KeyManager.UnmarshalBinary(pb.GetKeyManager()); err != nil {
		return err
	}

	c.ReplicaGroupSize = pb.GetReplicaGroupSize()
	c.ReplicaGroupBackupSize = pb.GetReplicaGroupBackupSize()
	c.ReplicaAllowedStragglers = pb.GetReplicaAllowedStragglers()
	c.StorageGroupSize = pb.GetStorageGroupSize()
	c.RegistrationTime = pb.GetRegistrationTime()
	c.Kind = RuntimeKind(pb.GetKind())

	return nil
}

// ToProto serializes a Runtime into a protobuf.
func (c *Runtime) ToProto() *pbRegistry.Runtime {
	pb := new(pbRegistry.Runtime)
	var err error

	if pb.Id, err = c.ID.MarshalBinary(); err != nil {
		panic(err)
	}
	if pb.TeeHardware, err = c.TEEHardware.ToProto(); err != nil {
		panic(err)
	}
	if pb.KeyManager, err = c.KeyManager.MarshalBinary(); err != nil {
		panic(err)
	}
	pb.ReplicaGroupSize = c.ReplicaGroupSize
	pb.ReplicaGroupBackupSize = c.ReplicaGroupBackupSize
	pb.ReplicaAllowedStragglers = c.ReplicaAllowedStragglers
	pb.StorageGroupSize = c.StorageGroupSize
	pb.RegistrationTime = c.RegistrationTime
	pb.Kind = uint32(c.Kind)

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
func SignRuntime(signer signature.Signer, context []byte, runtime *Runtime) (*SignedRuntime, error) {
	signed, err := signature.SignSigned(signer, context, runtime)
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

	// State is the state identified by the StateRoot. It may be empty iff
	// the StorageReceipt is not invalid or StateRoot is an empty hash.
	State storage.WriteLog `codec:"state"`

	// StorageReceipt is the storage receipt for the state root. It may be
	// invalid iff the State is non-empty or StateRoot is an empty hash.
	StorageReceipt signature.Signature `codec:"storage_receipt"`
}
