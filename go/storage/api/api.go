// Package api implements the storage backend API.
package api

import (
	"context"
	"errors"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	nodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	urkelNode "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

var (
	// ErrCantProve is the error returned when the backend is incapable
	// of generating proofs (unsupported, no key, etc).
	ErrCantProve = errors.New("storage: unable to provide proofs")
	// ErrNoRoots is the error returned when the generated receipt would
	// not contain any roots.
	ErrNoRoots = errors.New("storage: no roots to generate receipt for")
	// ErrExpectedRootMismatch is the error returned when the expected root
	// does not match the computed root.
	ErrExpectedRootMismatch = errors.New("storage: expected root mismatch")
	// ErrUnsupported is the error returned when the called method is not
	// supported by the given backend.
	ErrUnsupported = errors.New("storage: method not supported by backend")
	// ErrNoMergeRoots is the error returned when no other roots are passed
	// to the Merge operation.
	ErrNoMergeRoots = errors.New("storage: no roots to merge")

	// The following errors are reimports from NodeDB.

	// ErrNodeNotFound indicates that a node with the specified hash couldn't be found
	// in the database.
	ErrNodeNotFound = nodedb.ErrNodeNotFound
	// ErrWriteLogNotFound indicates that a write log for the specified storage hashes
	// couldn't be found.
	ErrWriteLogNotFound = nodedb.ErrWriteLogNotFound
	// ErrNotFinalized indicates that the operation requires a round to be finalized
	// but the round is not yet finalized.
	ErrNotFinalized = nodedb.ErrNotFinalized
	// ErrAlreadyFinalized indicates that the given round has already been finalized.
	ErrAlreadyFinalized = nodedb.ErrAlreadyFinalized
	// ErrRoundNotFound indicates that the given round cannot be found.
	ErrRoundNotFound = nodedb.ErrRoundNotFound
	// ErrPreviousRoundMismatch indicates that the round given for the old root does
	// not match the previous round.
	ErrPreviousRoundMismatch = nodedb.ErrPreviousRoundMismatch
	// ErrRoundWentBackwards indicates that the new round is earlier than an already
	// inserted round.
	ErrRoundWentBackwards = nodedb.ErrRoundWentBackwards
	// ErrRootNotFound indicates that the given root cannot be found.
	ErrRootNotFound = nodedb.ErrRootNotFound
	// ErrRootMustFollowOld indicates that the passed new root does not follow old root.
	ErrRootMustFollowOld = nodedb.ErrRootMustFollowOld

	// ReceiptSignatureContext is the signature context used for verifying MKVS receipts.
	ReceiptSignatureContext = []byte("EkStrRct")

	_ cbor.Marshaler   = (*ReceiptBody)(nil)
	_ cbor.Unmarshaler = (*ReceiptBody)(nil)
	_ cbor.Marshaler   = (*Receipt)(nil)
	_ cbor.Unmarshaler = (*Receipt)(nil)
)

// Config is the storage backend configuration.
type Config struct {
	// Backend is the database backend.
	Backend string

	// DB is the path to the database.
	DB string

	// Signer is the signing key to use for generating recipts.
	Signer signature.Signer

	// ApplyLockLRUSlots is the number of LRU slots to use for Apply call locks.
	ApplyLockLRUSlots uint64

	// InsecureSkipChecks bypasses the known root checks.
	InsecureSkipChecks bool
}

// ToNodeDB converts from a Config to a node DB Config.
func (cfg *Config) ToNodeDB() *nodedb.Config {
	return &nodedb.Config{
		DB: cfg.DB,
	}
}

// WriteLog is a write log.
//
// The keys in the write log must be unique.
type WriteLog = writelog.WriteLog

// LogEntry is a write log entry.
type LogEntry = writelog.LogEntry

// WriteLogIterator iterates over write log entries.
type WriteLogIterator = writelog.Iterator

// ReceiptBody is the body of a receipt.
type ReceiptBody struct {
	// Version is the storage data structure version.
	Version uint16 `codec:"version"`
	// Namespace is the chain namespace under which the root(s) are stored.
	Namespace common.Namespace `codec:"ns"`
	// Round is the chain round in which the root(s) are stored.
	Round uint64 `codec:"round"`
	// Roots are the merkle roots of the merklized data structure that the
	// storage node is certifying to store.
	Roots []hash.Hash `codec:"roots"`
}

// Receipt is a signed ReceiptBody.
type Receipt struct {
	signature.Signed
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (rb *ReceiptBody) MarshalCBOR() []byte {
	return cbor.Marshal(rb)
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (rb *ReceiptBody) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, rb)
}

// Open first verifies the blob signature then unmarshals the blob.
func (s *Receipt) Open(receipt *ReceiptBody) error {
	return s.Signed.Open(ReceiptSignatureContext, receipt)
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (s *Receipt) MarshalCBOR() []byte {
	return s.Signed.MarshalCBOR()
}

// UnmarshalCBOR deserializes a CBOR byte vector into the given type.
func (s *Receipt) UnmarshalCBOR(data []byte) error {
	return s.Signed.UnmarshalCBOR(data)
}

// SignReceipt signs a storage receipt for the given roots.
func SignReceipt(signer signature.Signer, ns common.Namespace, round uint64, roots []hash.Hash) (*Receipt, error) {
	if signer == nil {
		return nil, ErrCantProve
	}
	if len(roots) == 0 {
		return nil, ErrNoRoots
	}
	receipt := ReceiptBody{
		Version:   1,
		Namespace: ns,
		Round:     round,
		Roots:     roots,
	}
	signed, err := signature.SignSigned(signer, ReceiptSignatureContext, &receipt)
	if err != nil {
		return nil, err
	}

	return &Receipt{
		Signed: *signed,
	}, nil
}

// Root is a storage root.
type Root = urkelNode.Root

// Key is a node's key spelled out from the root to the node.
type Key = urkelNode.Key

// Depth determines the node's (bit) depth in the tree. It is also used for
// storing the Key length in bits.
type Depth = urkelNode.Depth

// Node is either an InternalNode or a LeafNode.
type Node = urkelNode.Node

// Pointer is a pointer to another node.
type Pointer = urkelNode.Pointer

// InternalNode is an internal node with two children.
type InternalNode = urkelNode.InternalNode

// LeafNode is a leaf node containing a key/value pair.
type LeafNode = urkelNode.LeafNode

// TreeID identifies a specific tree and a position within that tree.
type TreeID = syncer.TreeID

// GetRequest is a request for the SyncGet operation.
type GetRequest = syncer.GetRequest

// GetPrefixesRequest is a request for the SyncGetPrefixes operation.
type GetPrefixesRequest = syncer.GetPrefixesRequest

// IterateRequest is a request for the SyncIterate operation.
type IterateRequest = syncer.IterateRequest

// ProofResponse is a response for requests that produce proofs.
type ProofResponse = syncer.ProofResponse

// Proof is a Merkle proof for a subtree.
type Proof = syncer.Proof

// ApplyOp is an apply operation within a batch of apply operations.
type ApplyOp struct {
	// SrcRound is the source root round.
	SrcRound uint64
	// SrcRoot is the merkle root to apply the operations against. It may
	// refer to a nil node (empty hash) in which case a new root will be
	// created.
	SrcRoot hash.Hash
	// DstRoot is the expected merkle root after applying the write log.
	DstRoot hash.Hash
	// WriteLog is a write log of operations to apply.
	WriteLog WriteLog
}

// MergeOps is a merge operation within a batch of merge operations.
type MergeOp struct {
	// Base is the base root for the merge.
	Base hash.Hash
	// Others is a list of roots derived from base that should be merged.
	Others []hash.Hash
}

// Backend is a storage backend implementation.
type Backend interface {
	syncer.ReadSyncer

	// Apply applies a set of operations against the MKVS.  The root may refer
	// to a nil node, in which case a new root will be created.
	// The expected new root is used to check if the new root after all the
	// operations are applied already exists in the local DB.  If it does, the
	// Apply is ignored.
	Apply(
		ctx context.Context,
		ns common.Namespace,
		srcRound uint64,
		srcRoot hash.Hash,
		dstRound uint64,
		dstRoot hash.Hash,
		writeLog WriteLog,
	) ([]*Receipt, error)

	// ApplyBatch applies multiple sets of operations against the MKVS and
	// returns a single receipt covering all applied roots.
	//
	// See Apply for more details.
	ApplyBatch(
		ctx context.Context,
		ns common.Namespace,
		dstRound uint64,
		ops []ApplyOp,
	) ([]*Receipt, error)

	// TODO: Add proof.
	// Merge performs a 3-way merge operation between the specified
	// roots and returns a receipt for the merged root.
	//
	// Round is the round of the base root while all other roots are
	// expected to be in the next round.
	Merge(
		ctx context.Context,
		ns common.Namespace,
		round uint64,
		base hash.Hash,
		others []hash.Hash,
	) ([]*Receipt, error)

	// TODO: Add proof.
	// MergeBatch performs multiple sets of merge operations and returns
	// a single receipt covering all merged roots.
	//
	// See Merge for more details.
	MergeBatch(
		ctx context.Context,
		ns common.Namespace,
		round uint64,
		ops []MergeOp,
	) ([]*Receipt, error)

	// GetDiff returns an iterator of write log entries that must be applied
	// to get from the first given root to the second one.
	GetDiff(context.Context, Root, Root) (WriteLogIterator, error)

	// GetCheckpoint returns an iterator of write log entries in the provided
	// root.
	GetCheckpoint(context.Context, Root) (WriteLogIterator, error)

	// Cleanup closes/cleans up the storage backend.
	Cleanup()

	// Initialized returns a channel that will be closed when the
	// backend is initialized and ready to service requests.
	Initialized() <-chan struct{}
}

// LocalBackend is a storage implementation with a local backing store.
type LocalBackend interface {
	Backend

	// HasRoot checks if the storage backend contains the specified storage root.
	HasRoot(root Root) bool

	// Finalize finalizes the specified round. The passed list of roots are the
	// roots within the round that have been finalized. All non-finalized roots
	// can be discarded.
	Finalize(ctx context.Context, namespace common.Namespace, round uint64, roots []hash.Hash) error

	// Prune removes all roots recorded under the given namespace and round.
	//
	// Returns the number of pruned nodes.
	Prune(ctx context.Context, namespace common.Namespace, round uint64) (int, error)
}

// ClientBackend is a storage client backend implementation.
type ClientBackend interface {
	Backend

	// GetConnectedNodes returns currently connected storage nodes.
	GetConnectedNodes() []*node.Node

	// WatchRuntime adds a runtime for which client should keep track of scheduled storage nodes.
	WatchRuntime(signature.PublicKey) error
}
