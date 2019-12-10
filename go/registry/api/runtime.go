package api

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/prettyprint"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/version"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
)

var (
	// ErrInvalidRuntimeKind is the error returned when the parsed runtime
	// kind is malformed.
	ErrInvalidRuntimeKind = errors.New("runtime: invalid runtime kind")
	// ErrMalformedStoreID is the error returned when a storage service
	// ID is malformed.
	ErrMalformedStoreID = errors.New("runtime: Malformed store ID")

	_ prettyprint.PrettyPrinter = (*SignedRuntime)(nil)
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

	// TxnSchedulerAlgorithmBatching is the name of the batching algorithm.
	TxnSchedulerAlgorithmBatching = "batching"
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

// ComputeParameters are parameters for the compute committee.
type ComputeParameters struct {
	// GroupSize is the size of the committee.
	GroupSize uint64 `json:"group_size"`

	// GroupBackupSize is the size of the discrepancy resolution group.
	GroupBackupSize uint64 `json:"group_backup_size"`

	// AllowedStragglers is the number of allowed stragglers.
	AllowedStragglers uint64 `json:"allowed_stragglers"`

	// RoundTimeout is the round timeout of the nodes in the group.
	RoundTimeout time.Duration `json:"round_timeout"`
}

// MergeParameters are parameters for the merge committee.
type MergeParameters struct {
	// GroupSize is the size of the committee.
	GroupSize uint64 `json:"group_size"`

	// GroupBackupSize is the size of the discrepancy resolution group.
	GroupBackupSize uint64 `json:"group_backup_size"`

	// AllowedStragglers is the number of allowed stragglers.
	AllowedStragglers uint64 `json:"allowed_stragglers"`

	// RoundTimeout is the round timeout of the nodes in the group.
	RoundTimeout time.Duration `json:"round_timeout"`
}

// TxnSchedulerParameters are parameters for the transaction scheduler committee.
type TxnSchedulerParameters struct {
	// GroupSize is the size of the committee.
	GroupSize uint64 `json:"group_size"`

	// Algorithm is the transaction scheduling algorithm.
	Algorithm string `json:"algorithm"`

	// BatchFlushTimeout denotes, if using the "batching" algorithm, how long to
	// wait for a scheduled batch.
	BatchFlushTimeout time.Duration `json:"batch_flush_timeout"`

	// MaxBatchSize denotes, if using the "batching" algorithm, what is the max
	// size of a batch.
	MaxBatchSize uint64 `json:"max_batch_size"`

	// MaxBatchSizeBytes denotes, if using the "batching" algorithm, what is the
	// max size of a batch in bytes.
	MaxBatchSizeBytes uint64 `json:"max_batch_size_bytes"`
}

// StorageParameters are parameters for the storage committee.
type StorageParameters struct {
	// GroupSize is the size of the storage group.
	GroupSize uint64 `json:"group_size"`
}

// Runtime represents a runtime.
type Runtime struct {
	// ID is a globally unique long term identifier of the runtime.
	ID signature.PublicKey `json:"id"`

	// Genesis is the runtime genesis information.
	Genesis RuntimeGenesis `json:"genesis"`

	// Kind is the type of runtime.
	Kind RuntimeKind `json:"kind"`

	// TEEHardware specifies the runtime's TEE hardware requirements.
	TEEHardware node.TEEHardware `json:"tee_hardware"`

	// Version is the runtime version information.
	Version VersionInfo `json:"versions"`

	// KeyManager is the key manager runtime ID for this runtime.
	KeyManager *signature.PublicKey `json:"key_manager,omitempty"`

	// Compute stores parameters of the compute committee.
	Compute ComputeParameters `json:"compute,omitempty"`

	// Merge stores parameters of the merge committee.
	Merge MergeParameters `json:"merge,omitempty"`

	// TxnScheduler stores parameters of the transactions scheduler committee.
	TxnScheduler TxnSchedulerParameters `json:"txn_scheduler,omitempty"`

	// Storage stores parameters of the storage committee.
	Storage StorageParameters `json:"storage,omitempty"`
}

// String returns a string representation of itself.
func (c *Runtime) String() string {
	return "<Runtime id=" + c.ID.String() + ">"
}

// IsCompute returns true iff the runtime is a generic compute runtime.
func (c *Runtime) IsCompute() bool {
	return c.Kind == KindCompute
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
func (s SignedRuntime) PrettyPrint(prefix string, w io.Writer) {
	var rt Runtime
	if err := cbor.Unmarshal(s.Signed.Blob, &rt); err != nil {
		fmt.Fprintf(w, "%s<malformed: %s>\n", prefix, err)
		return
	}

	pp := signature.NewPrettySigned(s.Signed, rt)
	pp.PrettyPrint(prefix, w)
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
