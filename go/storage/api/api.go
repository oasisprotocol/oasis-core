// Package api implements the storage backend API.
package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	nodedb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	mkvsNode "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

const (
	// ModuleName is the storage module name.
	ModuleName = "storage"

	// WriteLogIteratorChunkSize defines the chunk size of write log entries
	// for the GetDiff method.
	WriteLogIteratorChunkSize = 10
)

var (
	// ErrCantProve is the error returned when the backend is incapable
	// of generating proofs (unsupported, no key, etc).
	ErrCantProve = errors.New(ModuleName, 1, "storage: unable to provide proofs")
	// ErrNoRoots is the error returned when the generated receipt would
	// not contain any roots.
	ErrNoRoots = errors.New(ModuleName, 2, "storage: no roots to generate receipt for")
	// ErrExpectedRootMismatch is the error returned when the expected root
	// does not match the computed root.
	ErrExpectedRootMismatch = errors.New(ModuleName, 3, "storage: expected root mismatch")
	// ErrUnsupported is the error returned when the called method is not
	// supported by the given backend.
	ErrUnsupported = errors.New(ModuleName, 4, "storage: method not supported by backend")
	// ErrLimitReached means that a configured limit has been reached.
	ErrLimitReached = errors.New(ModuleName, 5, "storage: limit reached")

	// The following errors are reimports from NodeDB.

	// ErrNodeNotFound indicates that a node with the specified hash couldn't be found
	// in the database.
	ErrNodeNotFound = nodedb.ErrNodeNotFound
	// ErrWriteLogNotFound indicates that a write log for the specified storage hashes
	// couldn't be found.
	ErrWriteLogNotFound = nodedb.ErrWriteLogNotFound
	// ErrNotFinalized indicates that the operation requires a version to be finalized
	// but the version is not yet finalized.
	ErrNotFinalized = nodedb.ErrNotFinalized
	// ErrAlreadyFinalized indicates that the given version has already been finalized.
	ErrAlreadyFinalized = nodedb.ErrAlreadyFinalized
	// ErrVersionNotFound indicates that the given version cannot be found.
	ErrVersionNotFound = nodedb.ErrVersionNotFound
	// ErrPreviousVersionMismatch indicates that the version given for the old root does
	// not match the previous version.
	ErrPreviousVersionMismatch = nodedb.ErrPreviousVersionMismatch
	// ErrVersionWentBackwards indicates that the new version is earlier than an already
	// inserted version.
	ErrVersionWentBackwards = nodedb.ErrVersionWentBackwards
	// ErrRootNotFound indicates that the given root cannot be found.
	ErrRootNotFound = nodedb.ErrRootNotFound
	// ErrRootMustFollowOld indicates that the passed new root does not follow old root.
	ErrRootMustFollowOld = nodedb.ErrRootMustFollowOld
	// ErrReadOnly indicates that the storage backend is read-only.
	ErrReadOnly = nodedb.ErrReadOnly

	// ReceiptSignatureContext is the signature context used for verifying MKVS receipts.
	ReceiptSignatureContext = signature.NewContext("oasis-core/storage: receipt", signature.WithChainSeparation())
)

// Config is the storage backend configuration.
type Config struct { // nolint: maligned
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

	// Namespace is the namespace contained within the database.
	Namespace common.Namespace

	// MaxCacheSize is the maximum in-memory cache size for the database.
	MaxCacheSize int64

	// DiscardWriteLogs will cause all write logs to be discarded.
	DiscardWriteLogs bool

	// NoFsync will disable fsync() where possible.
	NoFsync bool

	// MemoryOnly will make the storage memory-only (if the backend supports it).
	MemoryOnly bool

	// ReadOnly will make the storage read-only.
	ReadOnly bool
}

// ToNodeDB converts from a Config to a node DB Config.
func (cfg *Config) ToNodeDB() *nodedb.Config {
	return &nodedb.Config{
		DB:               cfg.DB,
		Namespace:        cfg.Namespace,
		MaxCacheSize:     cfg.MaxCacheSize,
		NoFsync:          cfg.NoFsync,
		MemoryOnly:       cfg.MemoryOnly,
		ReadOnly:         cfg.ReadOnly,
		DiscardWriteLogs: cfg.DiscardWriteLogs,
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
	Version uint16 `json:"version"`
	// Namespace is the chain namespace under which the root(s) are stored.
	Namespace common.Namespace `json:"ns"`
	// Round is the chain round in which the root(s) are stored.
	Round uint64 `json:"round"`
	// Roots are the merkle roots of the merklized data structure that the
	// storage node is certifying to store.
	Roots []hash.Hash `json:"roots"`
}

// Receipt is a signed ReceiptBody.
type Receipt struct {
	signature.Signed
}

// Open first verifies the blob signature then unmarshals the blob.
func (s *Receipt) Open(receipt *ReceiptBody) error {
	return s.Signed.Open(ReceiptSignatureContext, receipt)
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
type Root = mkvsNode.Root

// Key is a node's key spelled out from the root to the node.
type Key = mkvsNode.Key

// Depth determines the node's (bit) depth in the tree. It is also used for
// storing the Key length in bits.
type Depth = mkvsNode.Depth

// Node is either an InternalNode or a LeafNode.
type Node = mkvsNode.Node

// Pointer is a pointer to another node.
type Pointer = mkvsNode.Pointer

// InternalNode is an internal node with two children.
type InternalNode = mkvsNode.InternalNode

// LeafNode is a leaf node containing a key/value pair.
type LeafNode = mkvsNode.LeafNode

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

// NodeDB is a node database.
type NodeDB = nodedb.NodeDB

// ApplyOp is an apply operation within a batch of apply operations.
type ApplyOp struct {
	// SrcRound is the source root round.
	SrcRound uint64 `json:"src_round"`
	// SrcRoot is the merkle root to apply the operations against. It may
	// refer to a nil node (empty hash) in which case a new root will be
	// created.
	SrcRoot hash.Hash `json:"src_root"`
	// DstRoot is the expected merkle root after applying the write log.
	DstRoot hash.Hash `json:"dst_root"`
	// WriteLog is a write log of operations to apply.
	WriteLog WriteLog `json:"writelog"`
}

// ApplyRequest is an Apply request.
type ApplyRequest struct {
	Namespace common.Namespace `json:"namespace"`
	SrcRound  uint64           `json:"src_round"`
	SrcRoot   hash.Hash        `json:"src_root"`
	DstRound  uint64           `json:"dst_round"`
	DstRoot   hash.Hash        `json:"dst_root"`
	WriteLog  WriteLog         `json:"writelog"`
}

// ApplyBatchRequest is an ApplyBatch request.
type ApplyBatchRequest struct {
	Namespace common.Namespace `json:"namespace"`
	DstRound  uint64           `json:"dst_round"`
	Ops       []ApplyOp        `json:"ops"`
}

// SyncOptions are the sync options.
type SyncOptions struct {
	OffsetKey []byte `json:"offset_key"`
	Limit     uint64 `json:"limit"`
}

// SyncChunk is a chunk of write log entries sent during GetDiff operation.
type SyncChunk struct {
	Final    bool     `json:"final"`
	WriteLog WriteLog `json:"writelog"`
}

// GetDiffRequest is a GetDiff request.
type GetDiffRequest struct {
	StartRoot Root        `json:"start_root"`
	EndRoot   Root        `json:"end_root"`
	Options   SyncOptions `json:"options"`
}

// Backend is a storage backend implementation.
type Backend interface {
	syncer.ReadSyncer
	checkpoint.ChunkProvider

	// Apply applies a set of operations against the MKVS.  The root may refer
	// to a nil node, in which case a new root will be created.
	// The expected new root is used to check if the new root after all the
	// operations are applied already exists in the local DB.  If it does, the
	// Apply is ignored.
	Apply(ctx context.Context, request *ApplyRequest) ([]*Receipt, error)

	// ApplyBatch applies multiple sets of operations against the MKVS and
	// returns a single receipt covering all applied roots.
	//
	// See Apply for more details.
	ApplyBatch(ctx context.Context, request *ApplyBatchRequest) ([]*Receipt, error)

	// GetDiff returns an iterator of write log entries that must be applied
	// to get from the first given root to the second one.
	GetDiff(ctx context.Context, request *GetDiffRequest) (WriteLogIterator, error)

	// Cleanup closes/cleans up the storage backend.
	Cleanup()

	// Initialized returns a channel that will be closed when the
	// backend is initialized and ready to service requests.
	Initialized() <-chan struct{}
}

// LocalBackend is a storage implementation with a local backing store.
type LocalBackend interface {
	Backend

	// Checkpointer returns the checkpoint creator/restorer for this storage backend.
	Checkpointer() checkpoint.CreateRestorer

	// NodeDB returns the underlying node database.
	NodeDB() nodedb.NodeDB
}

// ClientBackend is a storage client backend implementation.
type ClientBackend interface {
	Backend

	// GetConnectedNodes returns currently connected storage nodes.
	GetConnectedNodes() []*node.Node

	// EnsureCommitteeVersion waits for the storage committee client to be fully synced to the
	// given version.
	EnsureCommitteeVersion(ctx context.Context, version int64) error
}
