// Package api provides a persistent node database interface for Urkel trees.
package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/errors"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/writelog"
)

// ModuleName is the module name.
const ModuleName = "storage/mkvs/db"

var (
	// ErrNodeNotFound indicates that a node with the specified hash couldn't be found
	// in the database.
	ErrNodeNotFound = errors.New(ModuleName, 1, "urkel: node not found in node db")
	// ErrWriteLogNotFound indicates that a write log for the specified storage hashes
	// couldn't be found.
	ErrWriteLogNotFound = errors.New(ModuleName, 2, "urkel: write log not found in node db")
	// ErrNotFinalized indicates that the operation requires a round to be finalized
	// but the round is not yet finalized.
	ErrNotFinalized = errors.New(ModuleName, 3, "urkel: round is not yet finalized")
	// ErrAlreadyFinalized indicates that the given round has already been finalized.
	ErrAlreadyFinalized = errors.New(ModuleName, 4, "urkel: round has already been finalized")
	// ErrRoundNotFound indicates that the given round cannot be found.
	ErrRoundNotFound = errors.New(ModuleName, 5, "urkel: round not found")
	// ErrPreviousRoundMismatch indicates that the round given for the old root does
	// not match the previous round.
	ErrPreviousRoundMismatch = errors.New(ModuleName, 6, "urkel: previous round mismatch")
	// ErrRoundWentBackwards indicates that the new round is earlier than an already
	// inserted round.
	ErrRoundWentBackwards = errors.New(ModuleName, 7, "urkel: round went backwards")
	// ErrRootNotFound indicates that the given root cannot be found.
	ErrRootNotFound = errors.New(ModuleName, 8, "urkel: root not found")
	// ErrRootMustFollowOld indicates that the passed new root does not follow old root.
	ErrRootMustFollowOld = errors.New(ModuleName, 9, "urkel: root must follow old root")
	// ErrBadNamespace indicates that the passed namespace does not match what is
	// actually contained within the database.
	ErrBadNamespace = errors.New(ModuleName, 10, "urkel: bad namespace")
)

// Config is the node database backend configuration.
type Config struct {
	// DB is the path to the database.
	DB string

	// DebugNoFsync will disable fsync() where possible.
	DebugNoFsync bool

	// Namespace is the namespace contained within the database.
	Namespace common.Namespace

	// MaxCacheSize is the maximum in-memory cache size for the database.
	MaxCacheSize int64
}

// NodeDB is the persistence layer used for persisting the in-memory tree.
type NodeDB interface {
	// GetNode lookups up a node in the database.
	GetNode(root node.Root, ptr *node.Pointer) (node.Node, error)

	// GetWriteLog retrieves a write log between two storage instances from the database.
	GetWriteLog(ctx context.Context, startRoot node.Root, endRoot node.Root) (writelog.Iterator, error)

	// NewBatch starts a new batch.
	//
	// The chunk argument specifies whether the given batch is being used to import a chunk of an
	// existing root. Chunks may contain unresolved pointers (e.g., pointers that point to hashes
	// which are not present in the database). Committing a chunk batch will prevent the round from
	// being finalized.
	NewBatch(oldRoot node.Root, chunk bool) Batch

	// HasRoot checks whether the given root exists.
	HasRoot(root node.Root) bool

	// Finalize finalizes the specified round. The passed list of roots are the
	// roots within the round that have been finalized. All non-finalized roots
	// can be discarded.
	Finalize(ctx context.Context, namespace common.Namespace, round uint64, roots []hash.Hash) error

	// Prune removes all roots recorded under the given namespace and round.
	//
	// Returns the number of pruned nodes.
	Prune(ctx context.Context, namespace common.Namespace, round uint64) (int, error)

	// Close closes the database.
	Close()
}

// Subtree is a NodeDB-specific subtree implementation.
type Subtree interface {
	// PutNode persists a node in the NodeDB.
	//
	// Depth is the node depth not bit depth.
	PutNode(depth node.Depth, ptr *node.Pointer) error

	// VisitCleanNode is called for any clean node encountered during commit
	// for which no further processing will be done (as it is marked clean).
	//
	// The specific NodeDB implementation may wish to do further processing.
	//
	// Depth is the node depth not bit depth.
	VisitCleanNode(depth node.Depth, ptr *node.Pointer) error

	// Commit marks the subtree as complete.
	Commit() error
}

// Batch is a NodeDB-specific batch implementation.
type Batch interface {
	// MaybeStartSubtree returns a new subtree instance that can be used for
	// persisting nodes under a given root.
	//
	// Depth is the depth of the node that subtreeRoot points to.
	MaybeStartSubtree(subtree Subtree, depth node.Depth, subtreeRoot *node.Pointer) Subtree

	// OnCommit registers a hook to run after a successful commit.
	OnCommit(hook func())

	// PutWriteLog stores the specified write log into the batch.
	PutWriteLog(writeLog writelog.WriteLog, logAnnotations writelog.Annotations) error

	// RemoveNodes marks nodes for eventual garbage collection.
	RemoveNodes(nodes []node.Node) error

	// Commit commits the batch.
	Commit(root node.Root) error

	// Reset resets the batch for another use.
	Reset()
}

// BaseBatch encapsulates basic functionality of a batch so it doesn't need
// to be reimplemented by each concrete batch implementation.
type BaseBatch struct {
	onCommitHooks []func()
}

func (b *BaseBatch) OnCommit(hook func()) {
	b.onCommitHooks = append(b.onCommitHooks, hook)
}

func (b *BaseBatch) Commit(root node.Root) error {
	for _, hook := range b.onCommitHooks {
		hook()
	}
	b.onCommitHooks = nil
	return nil
}

// nopNodeDB is a no-op node database which doesn't persist anything.
type nopNodeDB struct{}

// NewNopNodeDB creates a new no-op node database.
func NewNopNodeDB() (NodeDB, error) {
	return &nopNodeDB{}, nil
}

func (d *nopNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	return nil, ErrNodeNotFound
}

func (d *nopNodeDB) GetWriteLog(ctx context.Context, startRoot node.Root, endRoot node.Root) (writelog.Iterator, error) {
	return nil, ErrWriteLogNotFound
}

func (d *nopNodeDB) HasRoot(root node.Root) bool {
	return false
}

func (d *nopNodeDB) Finalize(ctx context.Context, namespace common.Namespace, round uint64, roots []hash.Hash) error {
	return nil
}

func (d *nopNodeDB) Prune(ctx context.Context, namespace common.Namespace, round uint64) (int, error) {
	return 0, nil
}

// Close is a no-op.
func (d *nopNodeDB) Close() {
}

// nopBatch is a no-op batch.
type nopBatch struct {
	BaseBatch
}

func (d *nopNodeDB) NewBatch(oldRoot node.Root, chunk bool) Batch {
	return &nopBatch{}
}

func (b *nopBatch) MaybeStartSubtree(subtree Subtree, depth node.Depth, subtreeRoot *node.Pointer) Subtree {
	return &nopSubtree{}
}

func (b *nopBatch) PutWriteLog(writeLog writelog.WriteLog, logAnnotations writelog.Annotations) error {
	return nil
}

func (b *nopBatch) RemoveNodes(nodes []node.Node) error {
	return nil
}

func (b *nopBatch) Reset() {
}

// nopSubtree is a no-op subtree.
type nopSubtree struct{}

func (s *nopSubtree) PutNode(depth node.Depth, ptr *node.Pointer) error {
	return nil
}

func (s *nopSubtree) VisitCleanNode(depth node.Depth, ptr *node.Pointer) error {
	return nil
}

func (s *nopSubtree) Commit() error {
	return nil
}
