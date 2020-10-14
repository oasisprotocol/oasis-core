// Package api provides a persistent node database interface for MKVS trees.
package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

// ModuleName is the module name.
const ModuleName = "storage/mkvs/db"

var (
	// ErrNodeNotFound indicates that a node with the specified hash couldn't be found
	// in the database.
	ErrNodeNotFound = errors.New(ModuleName, 1, "mkvs: node not found in node db")
	// ErrWriteLogNotFound indicates that a write log for the specified storage hashes
	// couldn't be found.
	ErrWriteLogNotFound = errors.New(ModuleName, 2, "mkvs: write log not found in node db")
	// ErrNotFinalized indicates that the operation requires a version to be finalized
	// but the version is not yet finalized.
	ErrNotFinalized = errors.New(ModuleName, 3, "mkvs: version is not yet finalized")
	// ErrAlreadyFinalized indicates that the given version has already been finalized.
	ErrAlreadyFinalized = errors.New(ModuleName, 4, "mkvs: version has already been finalized")
	// ErrVersionNotFound indicates that the given version cannot be found.
	ErrVersionNotFound = errors.New(ModuleName, 5, "mkvs: version not found")
	// ErrPreviousVersionMismatch indicates that the version given for the old root does
	// not match the previous version.
	ErrPreviousVersionMismatch = errors.New(ModuleName, 6, "mkvs: previous version mismatch")
	// ErrVersionWentBackwards indicates that the new version is earlier than an already
	// inserted version.
	ErrVersionWentBackwards = errors.New(ModuleName, 7, "mkvs: version went backwards")
	// ErrRootNotFound indicates that the given root cannot be found.
	ErrRootNotFound = errors.New(ModuleName, 8, "mkvs: root not found")
	// ErrRootMustFollowOld indicates that the passed new root does not follow old root.
	ErrRootMustFollowOld = errors.New(ModuleName, 9, "mkvs: root must follow old root")
	// ErrBadNamespace indicates that the passed namespace does not match what is
	// actually contained within the database.
	ErrBadNamespace = errors.New(ModuleName, 10, "mkvs: bad namespace")
	// ErrNotEarliest indicates that the given version is not the earliest version.
	ErrNotEarliest = errors.New(ModuleName, 11, "mkvs: version is not the earliest version")
	// ErrReadOnly indicates that a write operation failed due to a read-only database.
	ErrReadOnly = errors.New(ModuleName, 12, "mkvs: read-only database")
	// ErrMultipartInProgress indicates that a multipart restore operation is already
	// in progress.
	ErrMultipartInProgress = errors.New(ModuleName, 13, "mkvs: multipart already in progress")
	// ErrInvalidMultipartVersion indicates that a Finalize, NewBatch or Commit was called with a version
	// that doesn't match the current multipart restore as set with StartMultipartRestore.
	ErrInvalidMultipartVersion = errors.New(ModuleName, 14, "mkvs: operation called with different version than current multipart version")
)

// Config is the node database backend configuration.
type Config struct { // nolint: maligned
	// DB is the path to the database.
	DB string

	// NoFsync will disable fsync() where possible.
	NoFsync bool

	// MemoryOnly will make the storage memory-only (if the backend supports it).
	MemoryOnly bool

	// ReadOnly will make the storage read-only.
	ReadOnly bool

	// Namespace is the namespace contained within the database.
	Namespace common.Namespace

	// MaxCacheSize is the maximum in-memory cache size for the database.
	MaxCacheSize int64

	// DiscardWriteLogs will cause all write logs to be discarded.
	DiscardWriteLogs bool
}

// NodeDB is the persistence layer used for persisting the in-memory tree.
type NodeDB interface {
	// GetNode looks up a node in the database.
	GetNode(root node.Root, ptr *node.Pointer) (node.Node, error)

	// GetWriteLog retrieves a write log between two storage instances from the database.
	GetWriteLog(ctx context.Context, startRoot, endRoot node.Root) (writelog.Iterator, error)

	// GetLatestVersion returns the most recent version in the node database.
	GetLatestVersion(ctx context.Context) (uint64, error)

	// GetEarliestVersion returns the earliest version in the node database.
	GetEarliestVersion(ctx context.Context) (uint64, error)

	// GetRootsForVersion returns a list of roots stored under the given version.
	GetRootsForVersion(ctx context.Context, version uint64) ([]node.Root, error)

	// StartMultipartInsert prepares the database for a batch insert job from multiple chunks.
	// Batches from this call onwards will keep track of inserted nodes so that they can be
	// deleted if the job fails for any reason.
	StartMultipartInsert(version uint64) error

	// AbortMultipartInsert cleans up the node insertion log that was kept since the last
	// StartMultipartInsert operation. The log will be cleared and the associated nodes can
	// be either removed (if the insertion failed) or left intact (if it was successful).
	//
	// It is not an error to call this method more than once.
	AbortMultipartInsert() error

	// NewBatch starts a new batch.
	//
	// The chunk argument specifies whether the given batch is being used to import a chunk of an
	// existing root. Chunks may contain unresolved pointers (e.g., pointers that point to hashes
	// which are not present in the database). Committing a chunk batch will prevent the version
	// from being finalized.
	NewBatch(oldRoot node.Root, version uint64, chunk bool) (Batch, error)

	// HasRoot checks whether the given root exists.
	HasRoot(root node.Root) bool

	// Finalize finalizes the version comprising the passed list of finalized roots.
	// All non-finalized roots can be discarded.
	Finalize(ctx context.Context, roots []node.Root) error

	// Prune removes all roots recorded under the given version.
	//
	// Only the earliest version can be pruned, passing any other version will result in an error.
	Prune(ctx context.Context, version uint64) error

	// Size returns the size of the database in bytes.
	Size() (int64, error)

	// Sync syncs the database to disk. This is useful if the NoFsync option is used to explicitly
	// perform a sync.
	Sync() error

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

func (d *nopNodeDB) GetWriteLog(ctx context.Context, startRoot, endRoot node.Root) (writelog.Iterator, error) {
	return nil, ErrWriteLogNotFound
}

func (d *nopNodeDB) GetLatestVersion(ctx context.Context) (uint64, error) {
	return 0, nil
}

func (d *nopNodeDB) GetEarliestVersion(ctx context.Context) (uint64, error) {
	return 0, nil
}

func (d *nopNodeDB) GetRootsForVersion(ctx context.Context, version uint64) ([]node.Root, error) {
	return nil, nil
}

func (d *nopNodeDB) HasRoot(root node.Root) bool {
	return false
}

func (d *nopNodeDB) StartMultipartInsert(version uint64) error {
	return nil
}

func (d *nopNodeDB) AbortMultipartInsert() error {
	return nil
}

func (d *nopNodeDB) Finalize(ctx context.Context, roots []node.Root) error {
	return nil
}

func (d *nopNodeDB) Prune(ctx context.Context, version uint64) error {
	return nil
}

func (d *nopNodeDB) Size() (int64, error) {
	return 0, nil
}

func (d *nopNodeDB) Sync() error {
	return nil
}

func (d *nopNodeDB) Close() {
}

// nopBatch is a no-op batch.
type nopBatch struct {
	BaseBatch
}

func (d *nopNodeDB) NewBatch(oldRoot node.Root, version uint64, chunk bool) (Batch, error) {
	return &nopBatch{}, nil
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
