package api

import (
	"errors"
	"strings"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/sgx"
	"github.com/oasislabs/ekiden/go/common/version"
	pbRegistry "github.com/oasislabs/ekiden/go/grpc/registry"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

var (
	// ErrInvalidRuntimeKind is the error returned when the parsed runtime
	// kind is malformed.
	ErrInvalidRuntimeKind = errors.New("runtime: invalid runtime kind")
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

	kindCompute    = "compute"
	kindKeyManager = "keymanager"
)

// String returns a string representation of a runtime kind.
func (k RuntimeKind) String() string {
	switch k {
	case KindCompute:
		return kindCompute
	case KindKeyManager:
		return kindKeyManager
	default:
		return "[unsupported runtime kind]"
	}
}

// FromString deserializes a string into a RuntimeKind.
func (k *RuntimeKind) FromString(str string) error {
	switch strings.ToLower(str) {
	case kindCompute:
		*k = KindCompute
	case kindKeyManager:
		*k = KindKeyManager
	default:
		return ErrInvalidRuntimeKind
	}

	return nil
}

// Runtime represents a runtime.
type Runtime struct {
	// ID is a globally unique long term identifier of the runtime.
	ID signature.PublicKey `json:"id"`

	// Genesis is the runtime genesis information.
	Genesis RuntimeGenesis `json:"genesis"`

	// ReplicaGroupSize is the size of the computation group.
	ReplicaGroupSize uint64 `json:"replica_group_size"`

	// ReplicaGroupBackupSize is the size of the discrepancy resolution
	// replica group.
	ReplicaGroupBackupSize uint64 `json:"replica_group_backup_size"`

	// ReplicaAllowedStragglers is the number of allowed stragglers.
	ReplicaAllowedStragglers uint64 `json:"replica_allowed_stragglers"`

	// StorageGroupSize is the size of the storage group.
	StorageGroupSize uint64 `json:"storage_group_size"`

	// RegistrationTime is the time of registration of the runtime.
	RegistrationTime uint64 `json:"registration_time"`

	// TransactionSchedulerGroupSize the size of the TransactionScheduler group.
	TransactionSchedulerGroupSize uint64 `json:"transaction_scheduler_group_size"`

	// Kind is the type of runtime.
	Kind RuntimeKind `json:"kind"`

	// TEEHardware specifies the runtime's TEE hardware requirements.
	TEEHardware node.TEEHardware `json:"tee_hardware"`

	// Version is the runtime version information.
	Version VersionInfo `json:"versions"`

	// KeyManager is the key manager runtime ID for this runtime.
	KeyManager signature.PublicKey `json:"key_manager"`
}

// String returns a string representation of itself.
func (c *Runtime) String() string {
	return "<Runtime id=" + c.ID.String() + ">"
}

// IsCompute returns true iff the runtime is a generic compute runtime.
func (c *Runtime) IsCompute() bool {
	return c.Kind == KindCompute
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

	if err := c.Version.fromProto(pb.GetVersion()); err != nil {
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
	pb.Version = c.Version.toProto()
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

// VersionInfo is the per-runtime version information.
type VersionInfo struct {
	// Version of the runtime.
	Version version.Version `json:"version"`

	// TEE is the enclave version information, in an enclave provider specific
	// format if any.
	TEE []byte `json:"tee,omit_empty"`
}

func (v *VersionInfo) fromProto(pb *pbRegistry.VersionInfo) error {
	v.Version = version.FromU64(pb.GetVersion())
	v.TEE = append([]byte{}, pb.GetTee()...)
	return nil
}

func (v *VersionInfo) toProto() *pbRegistry.VersionInfo {
	pb := new(pbRegistry.VersionInfo)
	pb.Version = v.Version.ToU64()
	pb.Tee = append([]byte{}, v.TEE...)
	return pb
}

// VersionInfoIntelSGX is the SGX TEE version information.
type VersionInfoIntelSGX struct {
	// Enclaves is the allowed MRENCLAVE/MRSIGNER pairs.
	Enclaves []sgx.EnclaveIdentity `json:"enclaves"`
}

// RuntimeGenesis is the runtime genesis information that is used to
// initialize runtime state in the first block.
type RuntimeGenesis struct {
	// StateRoot is the state root that should be used at genesis time. If
	// the runtime should start with empty state, this must be set to the
	// empty hash.
	StateRoot hash.Hash `json:"state_root"`

	// State is the state identified by the StateRoot. It may be empty iff
	// the StorageReceipt is not invalid or StateRoot is an empty hash.
	State storage.WriteLog `json:"state"`

	// StorageReceipt is the storage receipt for the state root. It may be
	// invalid iff the State is non-empty or StateRoot is an empty hash.
	StorageReceipt signature.Signature `json:"storage_receipt"`
}
