package urkel

import (
	"context"
	"errors"
	"io"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/syncer"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/writelog"
)

var (
	// ErrClosed is the error returned when methods are used after Close is called.
	ErrClosed = errors.New("urkel: tree is closed")

	// ErrKnownRootMismatch is the error returned by CommitKnown when the known
	// root mismatches.
	ErrKnownRootMismatch = errors.New("urkel: known root mismatch")
)

// Tree is a MKVS tree interface.
type Tree interface {
	syncer.ReadSyncer

	// Insert inserts a key/value pair into the tree.
	Insert(ctx context.Context, key []byte, value []byte) error

	// Get looks up an existing key.
	Get(ctx context.Context, key []byte) ([]byte, error)

	// PrefetchPrefixes populates the in-memory tree with nodes for keys
	// starting with given prefixes.
	PrefetchPrefixes(ctx context.Context, prefixes [][]byte, limit uint16) error

	// RemoveExisting removes a key from the tree and returns the previous value.
	RemoveExisting(ctx context.Context, key []byte) ([]byte, error)

	// Remove removes a key from the tree.
	Remove(ctx context.Context, key []byte) error

	// NewIterator returns a new iterator over the tree.
	NewIterator(ctx context.Context, options ...IteratorOption) Iterator

	// ApplyWriteLog applies the operations from a write log to the current tree.
	//
	// The caller is responsible for calling Commit.
	ApplyWriteLog(ctx context.Context, wl writelog.Iterator) error

	// Close releases resources associated with this tree. After calling this
	// method the tree MUST NOT be used anymore and all methods will return
	// the ErrClosed error.
	//
	// Any pending write operations are discarded. If you need to persist them
	// you need to call Commit before calling this method.
	Close()

	// Size calculates the size of the tree in bytes.
	Size() uint64

	// CommitKnown checks that the computed root matches a known root and
	// if so, commits tree updates to the underlying database and returns
	// the write log.
	//
	// In case the computed root doesn't match the known root, the update
	// is NOT committed and ErrKnownRootMismatch is returned.
	CommitKnown(ctx context.Context, root node.Root) (writelog.WriteLog, error)

	// Commit commits tree updates to the underlying database and returns
	// the write log and new merkle root.
	Commit(ctx context.Context, namespace common.Namespace, round uint64) (writelog.WriteLog, hash.Hash, error)

	// DumpLocal dumps the tree in the local memory into the given writer.
	DumpLocal(ctx context.Context, w io.Writer, maxDepth node.Depth)
}
