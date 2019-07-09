// Package api provides a persistent node database interface for Urkel trees.
package api

import (
	"context"
	"errors"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

var (
	// ErrNodeNotFound indicates that a node with the specified hash couldn't be found in the database.
	ErrNodeNotFound = errors.New("urkel: node not found in node db")
	// ErrWriteLogNotFound indicates that a write log for the specified storage hashes couldn't be found.
	ErrWriteLogNotFound = errors.New("urkel: write log not found in node db")
)

// NodeDB is the persistence layer used for persisting the in-memory tree.
type NodeDB interface {
	// GetNode lookups up a node in the database.
	GetNode(root node.Root, ptr *node.Pointer) (node.Node, error)

	// GetWriteLog retrieves a write log between two storage instances from the database.
	GetWriteLog(ctx context.Context, startRoot node.Root, endRoot node.Root) (WriteLogIterator, error)

	// GetCheckpoint retrieves a write log of entries in root.
	GetCheckpoint(ctx context.Context, root node.Root) (WriteLogIterator, error)

	// NewBatch starts a new batch.
	NewBatch() Batch

	// HasRoot checks whether the given root exists.
	HasRoot(root node.Root) bool

	// Close closes the database.
	Close()
}

// Subtree is a NodeDB-specific subtree implementation.
type Subtree interface {
	// PutNode persists a node in the NodeDB.
	PutNode(depth uint8, ptr *node.Pointer) error

	// VisitCleanNode is called for any clean node encountered during commit
	// for which no further processing will be done (as it is marked clean).
	//
	// The specific NodeDB implementation may wish to do further processing.
	VisitCleanNode(depth uint8, ptr *node.Pointer) error

	// Commit marks the subtree as complete.
	Commit() error
}

// Batch is a NodeDB-specific batch implementation.
type Batch interface {
	// MaybeStartSubtree returns a new subtree instance that can be used for
	// persisting nodes under a given root.
	//
	// Depth is the depth of the node that subtreeRoot points to.
	MaybeStartSubtree(subtree Subtree, depth uint8, subtreeRoot *node.Pointer) Subtree

	// OnCommit registers a hook to run after a successful commit.
	OnCommit(hook func())

	// PutWriteLog stores the specified write log into the batch.
	PutWriteLog(
		startRoot node.Root,
		endRoot node.Root,
		writeLog writelog.WriteLog,
		logAnnotations writelog.WriteLogAnnotations,
	) error

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

// GetNode returns an ErrNodeNotFound error.
func (d *nopNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	return nil, ErrNodeNotFound
}

func (d *nopNodeDB) GetWriteLog(ctx context.Context, startRoot node.Root, endRoot node.Root) (WriteLogIterator, error) {
	return nil, ErrWriteLogNotFound
}

func (d *nopNodeDB) HasRoot(root node.Root) bool {
	return false
}

func (d *nopNodeDB) GetCheckpoint(ctx context.Context, root node.Root) (WriteLogIterator, error) {
	return nil, ErrWriteLogNotFound
}

// Close is a no-op.
func (d *nopNodeDB) Close() {
}

// nopBatch is a no-op batch.
type nopBatch struct {
	BaseBatch
}

func (d *nopNodeDB) NewBatch() Batch {
	return &nopBatch{}
}

func (b *nopBatch) MaybeStartSubtree(subtree Subtree, depth uint8, subtreeRoot *node.Pointer) Subtree {
	return &nopSubtree{}
}

func (b *nopBatch) PutWriteLog(
	startRoot node.Root,
	endRoot node.Root,
	writeLog writelog.WriteLog,
	logAnnotations writelog.WriteLogAnnotations,
) error {
	return nil
}

func (b *nopBatch) Reset() {
}

// nopSubtree is a no-op subtree.
type nopSubtree struct{}

func (s *nopSubtree) PutNode(depth uint8, ptr *node.Pointer) error {
	return nil
}

func (s *nopSubtree) VisitCleanNode(depth uint8, ptr *node.Pointer) error {
	return nil
}

func (s *nopSubtree) Commit() error {
	return nil
}

// CheckpointableDB encapsulates functionality of getting a checkpoint.
type CheckpointableDB struct {
	db NodeDB
}

// NewCheckpointableDB creates a new instance of CheckpoitableDb.
func NewCheckpointableDB(db NodeDB) CheckpointableDB {
	return CheckpointableDB{db: db}
}

// GetCheckpoint returns an iterator of write log entries in the provided
func (b *CheckpointableDB) GetCheckpoint(ctx context.Context, root node.Root) (WriteLogIterator, error) {
	if !b.db.HasRoot(root) {
		return nil, ErrNodeNotFound
	}
	ptr := &node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	}
	pipe := NewPipeWriteLogIterator(ctx)
	go func() {
		defer pipe.Close()

		b.getNodeWriteLog(ctx, &pipe, root, ptr)
	}()

	return &pipe, nil
}

func (b *CheckpointableDB) getNodeWriteLog(ctx context.Context, pipe *PipeWriteLogIterator, root node.Root, ptr *node.Pointer) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	nod, err := b.db.GetNode(root, ptr)
	if err != nil {
		_ = pipe.PutError(err)
		return
	}
	switch n := nod.(type) {
	case *node.LeafNode:
		entry := writelog.LogEntry{
			Key:   n.Key[:],
			Value: n.Value.Value[:],
		}
		if err := pipe.Put(&entry); err != nil {
			_ = pipe.PutError(err)
		}
	case *node.InternalNode:
		if n.Left != nil {
			b.getNodeWriteLog(ctx, pipe, root, n.Left)
		}
		if n.Right != nil {
			b.getNodeWriteLog(ctx, pipe, root, n.Right)
		}
	default:
		panic("urkel/db/CheckpoitableDB: invalid root node type")
	}
}
