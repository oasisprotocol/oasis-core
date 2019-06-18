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

	// GetNode lookups up a value in the database.
	GetValue(id hash.Hash) ([]byte, error)

	// NewBatch starts a new batch.
	NewBatch() Batch

	// Close closes the database.
	Close()
}

// Batch is a NodeDB-specific batch implementation.
type Batch interface {
	// PutNode inserts a node into the database. If a node already
	// exists it increments its reference counter.
	//
	// The passed pointer's DBInternal may be modified by this call.
	PutNode(ptr *internal.Pointer) error

	// RemoveNode decrements the reference counter on the node with the
	// given identifier. If the reference counter becomes negative
	// it removes the node.
	//
	// The passed pointer's DBInternal may be modified by this call.
	RemoveNode(ptr *internal.Pointer) error

	// PutValue inserts a value into the database. If a value already
	// exists it increments its reference counter.
	PutValue(value []byte) error

	// RemoveValue decrements the reference counter on the value with the
	// given identifier. If the reference counter becomes negative
	// it removes the value.
	RemoveValue(id hash.Hash) error

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

// PutNode does nothing.
func (b *nopBatch) PutNode(ptr *internal.Pointer) error {
	return nil
}

// RemoveNode does nothing.
func (b *nopBatch) RemoveNode(ptr *internal.Pointer) error {
	return nil
}

// PutValue does nothing.
func (b *nopBatch) PutValue(value []byte) error {
	return nil
}

// RemoveValue does nothing.
func (b *nopBatch) RemoveValue(id hash.Hash) error {
	return nil
}

// Commit does nothing.
func (b *nopBatch) Commit(root hash.Hash) error {
	return nil
}

// Reset does nothing.
func (b *nopBatch) Reset() {
}
