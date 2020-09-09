package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

var (
	// ErrUnsupportedRuntimeKind is the error returned when the parsed runtime
	// kind is malformed or unknown.
	ErrUnsupportedRuntimeKind = errors.New("runtime: unsupported runtime kind")

	_ prettyprint.PrettyPrinter = (*SignedRuntime)(nil)
)

// RuntimeKind represents the runtime functionality.
type RuntimeKind uint32

const (
	// KindInvalid is an invalid runtime and should never be explicitly set.
	KindInvalid RuntimeKind = 0

	// KindCompute is a generic compute runtime.
	KindCompute RuntimeKind = 1

	// KindKeyManager is a key manager runtime.
	KindKeyManager RuntimeKind = 2

	kindInvalid    = "invalid"
	kindCompute    = "compute"
	kindKeyManager = "keymanager"

	// TxnSchedulerSimple is the name of the simple batching algorithm.
	TxnSchedulerSimple = "simple"
)

// String returns a string representation of a runtime kind.
func (k RuntimeKind) String() string {
	switch k {
	case KindInvalid:
		return kindInvalid
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
		return ErrUnsupportedRuntimeKind
	}

	return nil
}

// ExecutorParameters are parameters for the executor committee.
type ExecutorParameters struct {
	// GroupSize is the size of the committee.
	GroupSize uint64 `json:"group_size"`

	// GroupBackupSize is the size of the discrepancy resolution group.
	GroupBackupSize uint64 `json:"group_backup_size"`

	// AllowedStragglers is the number of allowed stragglers.
	AllowedStragglers uint64 `json:"allowed_stragglers"`

	// RoundTimeout is the round timeout in consensus blocks.
	RoundTimeout int64 `json:"round_timeout"`
}

// ValidateBasic performs basic executor parameter validity checks.
func (e *ExecutorParameters) ValidateBasic() error {
	if e.GroupSize == 0 {
		return fmt.Errorf("executor primary group too small")
	}
	if e.AllowedStragglers > e.GroupSize || (e.GroupBackupSize > 0 && e.AllowedStragglers > e.GroupBackupSize) {
		return fmt.Errorf("number of allowed stragglers too large")
	}

	if e.RoundTimeout < 5 {
		return fmt.Errorf("round timeout too small")
	}
	return nil
}

// TxnSchedulerParameters are parameters for the runtime transaction scheduler.
type TxnSchedulerParameters struct {
	// Algorithm is the transaction scheduling algorithm.
	Algorithm string `json:"algorithm"`

	// BatchFlushTimeout denotes, if using the "simple" algorithm, how long to
	// wait for a scheduled batch.
	BatchFlushTimeout time.Duration `json:"batch_flush_timeout"`

	// MaxBatchSize denotes what is the max size of a scheduled batch.
	MaxBatchSize uint64 `json:"max_batch_size"`

	// MaxBatchSizeBytes denote what is the max size of a scheduled batch in bytes.
	MaxBatchSizeBytes uint64 `json:"max_batch_size_bytes"`

	// ProposerTimeout denotes the timeout (in consensus blocks) for scheduler
	// to propose a batch.
	ProposerTimeout int64 `json:"propose_batch_timeout"`
}

// ValidateBasic performs basic transaction scheduler parameter validity checks.
func (t *TxnSchedulerParameters) ValidateBasic() error {
	// Ensure txnscheduler parameters have sensible values.
	if t.Algorithm != TxnSchedulerSimple {
		return fmt.Errorf("invalid transaction scheduler algorithm")
	}
	if t.BatchFlushTimeout < 50*time.Millisecond {
		return fmt.Errorf("transaction scheduler batch flush timeout parameter too small")
	}
	if t.MaxBatchSize < 1 {
		return fmt.Errorf("transaction scheduler max batch size parameter too small")
	}
	if t.MaxBatchSizeBytes < 1024 {
		return fmt.Errorf("transaction scheduler max batch bytes size parameter too small")
	}
	if t.ProposerTimeout < 5 {
		return fmt.Errorf("transaction scheduler proposer timeout parameter too small")
	}

	return nil
}

// StorageParameters are parameters for the storage committee.
type StorageParameters struct {
	// GroupSize is the size of the storage group.
	GroupSize uint64 `json:"group_size"`

	// MinWriteReplication is the number of nodes to which any writes must be replicated before
	// being assumed to be committed. It must be less than or equal to the GroupSize.
	MinWriteReplication uint64 `json:"min_write_replication"`

	// MaxApplyWriteLogEntries is the maximum number of write log entries when performing an Apply
	// operation.
	MaxApplyWriteLogEntries uint64 `json:"max_apply_write_log_entries"`

	// MaxApplyOps is the maximum number of apply operations in a batch.
	MaxApplyOps uint64 `json:"max_apply_ops"`

	// CheckpointInterval is the expected runtime state checkpoint interval (in rounds).
	CheckpointInterval uint64 `json:"checkpoint_interval"`

	// CheckpointNumKept is the expected minimum number of checkpoints to keep.
	CheckpointNumKept uint64 `json:"checkpoint_num_kept"`

	// CheckpointChunkSize is the chunk size parameter for checkpoint creation.
	CheckpointChunkSize uint64 `json:"checkpoint_chunk_size"`
}

// ValidateBasic performs basic storage parameter validity checks.
func (s *StorageParameters) ValidateBasic() error {
	// Ensure there is at least one member of the storage group.
	if s.GroupSize == 0 {
		return fmt.Errorf("storage group too small")
	}
	if s.MinWriteReplication == 0 {
		return fmt.Errorf("storage write replication factor must be non-zero")
	}
	if s.MinWriteReplication > s.GroupSize {
		return fmt.Errorf("storage write replication factor must be less than or equal to group size")
	}

	// Ensure limit parameters have sensible values.
	if s.MaxApplyWriteLogEntries < 10 {
		return fmt.Errorf("storage MaxApplyWriteLogEntries parameter too small")
	}
	if s.MaxApplyOps < 2 {
		return fmt.Errorf("storage MaxApplyOps parameter too small")
	}

	// Verify storage checkpointing configuration if enabled.
	if s.CheckpointInterval > 0 && !flags.DebugDontBlameOasis() {
		if s.CheckpointInterval < 10 {
			return fmt.Errorf("storage CheckpointInterval parameter too small")
		}
		if s.CheckpointNumKept == 0 {
			return fmt.Errorf("storage CheckpointNumKept parameter too small")
		}
		if s.CheckpointChunkSize < 1024*1024 {
			return fmt.Errorf("storage CheckpointChunkSize parameter too small")
		}
	}
	return nil
}

// AnyNodeRuntimeAdmissionPolicy allows any node to register.
type AnyNodeRuntimeAdmissionPolicy struct{}

// EntityWhitelistRuntimeAdmissionPolicy allows only whitelisted entities' nodes to register.
type EntityWhitelistRuntimeAdmissionPolicy struct {
	Entities map[signature.PublicKey]bool `json:"entities"`
}

// RuntimeAdmissionPolicy is a specification of which nodes are allowed to register for a runtime.
type RuntimeAdmissionPolicy struct {
	AnyNode         *AnyNodeRuntimeAdmissionPolicy         `json:"any_node,omitempty"`
	EntityWhitelist *EntityWhitelistRuntimeAdmissionPolicy `json:"entity_whitelist,omitempty"`
}

// RuntimeStakingParameters are the stake-related parameters for a runtime.
type RuntimeStakingParameters struct {
	// Thresholds are the minimum stake thresholds for a runtime. These per-runtime thresholds are
	// in addition to the global thresholds. May be left unspecified.
	//
	// In case a node is registered for multiple runtimes, it will need to satisfy the maximum
	// threshold of all the runtimes.
	Thresholds map[staking.ThresholdKind]quantity.Quantity `json:"thresholds,omitempty"`
}

// ValidateBasic performs basic descriptor validity checks.
func (s *RuntimeStakingParameters) ValidateBasic(runtimeKind RuntimeKind) error {
	for kind, q := range s.Thresholds {
		switch kind {
		case staking.KindNodeCompute, staking.KindNodeStorage:
			if runtimeKind != KindCompute {
				return fmt.Errorf("unsupported staking threshold kind for runtime: %s", kind)
			}
		case staking.KindNodeKeyManager:
			if runtimeKind != KindKeyManager {
				return fmt.Errorf("unsupported staking threshold kind for runtime: %s", kind)
			}
		default:
			return fmt.Errorf("unsupported staking threshold kind for runtime: %s", kind)
		}

		if !q.IsValid() {
			return fmt.Errorf("invalid threshold of kind %s specified", kind)
		}
	}
	return nil
}

const (
	// LatestRuntimeDescriptorVersion is the latest entity descriptor version that should be used
	// for all new descriptors. Using earlier versions may be rejected.
	LatestRuntimeDescriptorVersion = 1

	// Minimum and maximum descriptor versions that are allowed.
	minRuntimeDescriptorVersion = 1
	maxRuntimeDescriptorVersion = LatestRuntimeDescriptorVersion
)

// Runtime represents a runtime.
type Runtime struct { // nolint: maligned
	cbor.Versioned

	// ID is a globally unique long term identifier of the runtime.
	ID common.Namespace `json:"id"`

	// EntityID is the public key identifying the Entity controlling
	// the runtime.
	EntityID signature.PublicKey `json:"entity_id"`

	// Genesis is the runtime genesis information.
	Genesis RuntimeGenesis `json:"genesis"`

	// Kind is the type of runtime.
	Kind RuntimeKind `json:"kind"`

	// TEEHardware specifies the runtime's TEE hardware requirements.
	TEEHardware node.TEEHardware `json:"tee_hardware"`

	// Version is the runtime version information.
	Version VersionInfo `json:"versions"`

	// KeyManager is the key manager runtime ID for this runtime.
	KeyManager *common.Namespace `json:"key_manager,omitempty"`

	// Executor stores parameters of the executor committee.
	Executor ExecutorParameters `json:"executor,omitempty"`

	// TxnScheduler stores transaction scheduling parameters of the executor
	// committee.
	TxnScheduler TxnSchedulerParameters `json:"txn_scheduler,omitempty"`

	// Storage stores parameters of the storage committee.
	Storage StorageParameters `json:"storage,omitempty"`

	// AdmissionPolicy sets which nodes are allowed to register for this runtime.
	// This policy applies to all roles.
	AdmissionPolicy RuntimeAdmissionPolicy `json:"admission_policy"`

	// Staking stores the runtime's staking-related parameters.
	Staking RuntimeStakingParameters `json:"staking,omitempty"`
}

// ValidateBasic performs basic descriptor validity checks.
func (r *Runtime) ValidateBasic(strictVersion bool) error {
	v := r.Versioned.V
	switch strictVersion {
	case true:
		// Only the latest version is allowed.
		if v != LatestRuntimeDescriptorVersion {
			return fmt.Errorf("invalid runtime descriptor version (expected: %d got: %d)",
				LatestRuntimeDescriptorVersion,
				v,
			)
		}
	case false:
		// A range of versions is allowed.
		if v < minRuntimeDescriptorVersion || v > maxRuntimeDescriptorVersion {
			return fmt.Errorf("invalid runtime descriptor version (min: %d max: %d)",
				minRuntimeDescriptorVersion,
				maxRuntimeDescriptorVersion,
			)
		}
	}

	switch r.Kind {
	case KindCompute:
		// Compute runtime
		if r.ID.IsKeyManager() {
			return fmt.Errorf("compute runtime ID has the key manager flag set")
		}
		if r.KeyManager != nil && r.ID.Equal(r.KeyManager) {
			return fmt.Errorf("compute runtime has self as key manager")
		}

		if err := r.Executor.ValidateBasic(); err != nil {
			return fmt.Errorf("bad executor parameters: %w", err)
		}
		if err := r.TxnScheduler.ValidateBasic(); err != nil {
			return fmt.Errorf("bad txn scheduler parameters: %w", err)
		}
		if err := r.Storage.ValidateBasic(); err != nil {
			return fmt.Errorf("bad storage parameters: %w", err)
		}
	case KindKeyManager:
		// Key manager runtime.
		if !r.ID.IsKeyManager() {
			return fmt.Errorf("key manager runtime ID does not have the key manager flag set")
		}
		if r.KeyManager != nil {
			return fmt.Errorf("key manager runtime cannot itself have a key manager")
		}

		// Currently the keymanager implementation assumes SGX. Unless this is a
		// test runtime, a keymanager without SGX is disallowed.
		if !r.ID.IsTest() && r.TEEHardware != node.TEEHardwareIntelSGX {
			return fmt.Errorf("non-SGX keymanager runtime")
		}
	default:
		return fmt.Errorf("bad runtime kind: %s", r.Kind)
	}

	if err := r.Staking.ValidateBasic(r.Kind); err != nil {
		return fmt.Errorf("bad staking parameters: %w", err)
	}
	return nil
}

// String returns a string representation of itself.
func (r Runtime) String() string {
	return "<Runtime id=" + r.ID.String() + ">"
}

// IsCompute returns true iff the runtime is a generic compute runtime.
func (r *Runtime) IsCompute() bool {
	return r.Kind == KindCompute
}

// SignedRuntime is a signed blob containing a CBOR-serialized Runtime.
type SignedRuntime struct {
	signature.Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedRuntime) Open(context signature.Context, runtime *Runtime) error { // nolint: interfacer
	return s.Signed.Open(context, runtime)
}

// PrettyPrint writes a pretty-printed representation of the type
// to the given writer.
func (s SignedRuntime) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	pt, err := s.PrettyType()
	if err != nil {
		fmt.Fprintf(w, "%s<error: %s>\n", prefix, err)
		return
	}

	pt.(prettyprint.PrettyPrinter).PrettyPrint(ctx, prefix, w)
}

// PrettyType returns a representation of the type that can be used for pretty printing.
func (s SignedRuntime) PrettyType() (interface{}, error) {
	var rt Runtime
	if err := cbor.Unmarshal(s.Signed.Blob, &rt); err != nil {
		return nil, fmt.Errorf("malformed signed blob: %w", err)
	}
	return signature.NewPrettySigned(s.Signed, rt)
}

// SignRuntime serializes the Runtime and signs the result.
func SignRuntime(signer signature.Signer, context signature.Context, runtime *Runtime) (*SignedRuntime, error) {
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
	TEE []byte `json:"tee,omitempty"`
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
	// all StorageReceipts are valid or StateRoot is an empty hash or if used
	// in network genesis (e.g. during consensus chain init).
	State storage.WriteLog `json:"state"`

	// StorageReceipts are the storage receipts for the state root. The list
	// may be empty or a signature in the list invalid iff the State is non-
	// empty or StateRoot is an empty hash or if used in network genesis
	// (e.g. during consensus chain init).
	StorageReceipts []signature.Signature `json:"storage_receipts"`

	// Round is the runtime round in the genesis.
	Round uint64 `json:"round"`
}

// Equal compares vs another RuntimeGenesis for equality.
func (rtg *RuntimeGenesis) Equal(cmp *RuntimeGenesis) bool {
	if !rtg.StateRoot.Equal(&cmp.StateRoot) {
		return false
	}
	if rtg.Round != cmp.Round {
		return false
	}
	if !rtg.State.Equal(cmp.State) {
		return false
	}
	if len(rtg.StorageReceipts) != len(cmp.StorageReceipts) {
		return false
	}
	for k, v := range rtg.StorageReceipts {
		if !v.Equal(&cmp.StorageReceipts[k]) {
			return false
		}
	}
	return true
}

// SanityCheck does basic sanity checking of RuntimeGenesis.
// isGenesis is true, if it is called during consensus chain init.
func (rtg *RuntimeGenesis) SanityCheck(isGenesis bool) error {
	if isGenesis {
		return nil
	}

	// Require that either State is non-empty or Storage receipt being valid or StateRoot being non-empty.
	if len(rtg.State) == 0 && !rtg.StateRoot.IsEmpty() {
		// If State is empty and StateRoot is not, then all StorageReceipts must correctly verify StorageRoot.
		if len(rtg.StorageReceipts) == 0 {
			return fmt.Errorf("runtimegenesis: sanity check failed: when State is empty either StorageReceipts must be populated or StateRoot must be empty")
		}
		for _, sr := range rtg.StorageReceipts {
			if !sr.PublicKey.IsValid() {
				return fmt.Errorf("runtimegenesis: sanity check failed: when State is empty either all StorageReceipts must be valid or StateRoot must be empty (public_key %s)", sr.PublicKey)
			}

			// TODO: Even if Verify below succeeds, runtime registration should still be rejected until oasis-core#1686 is solved!
			if !sr.Verify(storage.ReceiptSignatureContext, rtg.StateRoot[:]) {
				return fmt.Errorf("runtimegenesis: sanity check failed: StorageReceipt verification on StateRoot failed (public_key %s)", sr.PublicKey)
			}
		}
	}

	return nil
}

// RuntimeDescriptorProvider is an interface that provides access to runtime descriptors.
type RuntimeDescriptorProvider interface {
	// RegistryDescriptor waits for the runtime to be registered and then returns its registry
	// descriptor.
	RegistryDescriptor(ctx context.Context) (*Runtime, error)
}
