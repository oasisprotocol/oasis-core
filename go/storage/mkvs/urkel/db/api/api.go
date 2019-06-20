// Package api provides a persistent node database interface for Urkel trees.
package api

import (
	"errors"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

var ErrNodeNotFound = errors.New("urkel: node not found in node db")

// NodeDB is the persistence layer used for persisting the in-memory tree.
type NodeDB interface {
	// GetNode lookups up a node in the database.
	GetNode(root hash.Hash, ptr *internal.Pointer) (internal.Node, error)

	// GetValue lookups up a value in the database.
	GetValue(id hash.Hash) ([]byte, error)

	// NewBatch starts a new batch.
	NewBatch() Batch

	// Close closes the database.
	Close()
}

// Subtree is a NodeDB-specific subtree implementation.
type Subtree interface {
	// PutNode persists a node in the NodeDB.
	PutNode(depth uint8, ptr *internal.Pointer) error

	// VisitCleanNode is called for any clean node encountered during commit
	// for which no further processing will be done (as it is marked clean).
	//
	// The specific NodeDB implementation may wish to do further processing.
	VisitCleanNode(depth uint8, ptr *internal.Pointer) error

	// Commit marks the subtree as complete.
	Commit() error
}

// Batch is a NodeDB-specific batch implementation.
type Batch interface {
	// MaybeStartSubtree returns a new subtree instance that can be used for
	// persisting nodes under a given root.
	//
	// Depth is the depth of the node that subtreeRoot points to.
	MaybeStartSubtree(subtree Subtree, depth uint8, subtreeRoot *internal.Pointer) Subtree

	// Commit commits the batch.
	Commit(root hash.Hash) error

	// Reset resets the batch for another use.
	Reset()
}

// nopNodeDB is a no-op node database which doesn't persist anything.
type nopNodeDB struct{}

// NewNopNodeDB creates a new no-op node database.
func NewNopNodeDB() (NodeDB, error) {
	return &nopNodeDB{}, nil
}

// GetNode returns an ErrNodeNotFound error.
func (d *nopNodeDB) GetNode(root hash.Hash, ptr *internal.Pointer) (internal.Node, error) {
	return nil, ErrNodeNotFound
}

// GetValue returns an ErrNodeNotFound error.
func (d *nopNodeDB) GetValue(id hash.Hash) ([]byte, error) {
	return nil, ErrNodeNotFound
}

// Close is a no-op.
func (d *nopNodeDB) Close() {
}

// nopBatch is a no-op batch.
type nopBatch struct{}

func (d *nopNodeDB) NewBatch() Batch {
	return &nopBatch{}
}

func (b *nopBatch) MaybeStartSubtree(subtree Subtree, depth uint8, subtreeRoot *internal.Pointer) Subtree {
	return &nopSubtree{}
}

// Commit does nothing.
func (b *nopBatch) Commit(root hash.Hash) error {
	return nil
}

// Reset does nothing.
func (b *nopBatch) Reset() {
}

// nopSubtree is a no-op subtree.
type nopSubtree struct{}

func (s *nopSubtree) PutNode(depth uint8, ptr *internal.Pointer) error {
	return nil
}

func (s *nopSubtree) VisitCleanNode(depth uint8, ptr *internal.Pointer) error {
	return nil
}

func (s *nopSubtree) Commit() error {
	return nil
}
