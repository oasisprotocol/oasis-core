package mkvs

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

var _ OverlayTree = (*treeOverlay)(nil)

type treeOverlay struct {
	inner   Tree
	overlay Tree

	dirty map[string]bool
}

// NewOverlay creates a new key-value tree overlay that holds all updates in memory and only commits
// them if requested. This can be used to create snapshots that can be discarded.
//
// While updates (inserts, removes) are stored in the overlay, reads are not cached in the overlay
// as the inner tree has its own cache and double caching makes less sense.
//
// The overlay is not safe for concurrent use.
func NewOverlay(inner Tree) OverlayTree {
	return &treeOverlay{
		inner:   inner,
		overlay: New(nil, nil, WithoutWriteLog()),
		dirty:   make(map[string]bool),
	}
}

// Implements KeyValueTree.
func (o *treeOverlay) Insert(ctx context.Context, key, value []byte) error {
	err := o.overlay.Insert(ctx, key, value)
	if err != nil {
		return err
	}

	o.dirty[string(key)] = true
	return nil
}

// Implements KeyValueTree.
func (o *treeOverlay) Get(ctx context.Context, key []byte) ([]byte, error) {
	// For dirty values, check the overlay.
	if o.dirty[string(key)] {
		return o.overlay.Get(ctx, key)
	}

	// Otherwise fetch from inner tree.
	return o.inner.Get(ctx, key)
}

// Implements KeyValueTree.
func (o *treeOverlay) RemoveExisting(ctx context.Context, key []byte) ([]byte, error) {
	// For dirty values, remove from the overlay.
	if o.dirty[string(key)] {
		return o.overlay.RemoveExisting(ctx, key)
	}

	value, err := o.inner.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	// Do not treat a value as dirty if it was not dirty before and did not exist in the inner tree.
	if value != nil {
		o.dirty[string(key)] = true
	}
	return value, nil
}

// Implements KeyValueTree.
func (o *treeOverlay) Remove(ctx context.Context, key []byte) error {
	// Since we don't care about the previous value, we can just record an update.
	o.dirty[string(key)] = true
	return o.overlay.Remove(ctx, key)
}

// Implements KeyValueTree.
func (o *treeOverlay) NewIterator(ctx context.Context, options ...IteratorOption) Iterator {
	return &treeOverlayIterator{
		tree:    o,
		inner:   o.inner.NewIterator(ctx, options...),
		overlay: o.overlay.NewIterator(ctx),
	}
}

// Implements OverlayTree.
func (o *treeOverlay) Commit(ctx context.Context) error {
	it := o.overlay.NewIterator(ctx)
	defer it.Close()

	// Insert all items present in the overlay.
	for it.Rewind(); it.Valid(); it.Next() {
		if err := o.inner.Insert(ctx, it.Key(), it.Value()); err != nil {
			return err
		}
		delete(o.dirty, string(it.Key()))
	}
	if it.Err() != nil {
		return it.Err()
	}

	// Any remaining dirty items must have been removed.
	for key := range o.dirty {
		if err := o.inner.Remove(ctx, []byte(key)); err != nil {
			return err
		}
	}

	return nil
}

// Implements ClosableTree.
func (o *treeOverlay) Close() {
	if o.inner == nil {
		return
	}

	o.overlay.Close()

	o.inner = nil
	o.overlay = nil
	o.dirty = nil
}

type treeOverlayIterator struct {
	tree *treeOverlay

	inner   Iterator
	overlay Iterator

	key   node.Key
	value []byte
}

func (it *treeOverlayIterator) Valid() bool {
	// If either iterator is valid, the merged iterator is valid.
	return it.inner.Valid() || it.overlay.Valid()
}

func (it *treeOverlayIterator) Err() error {
	// If either iterator has an error, the merged iterator has an error.
	if err := it.inner.Err(); err != nil {
		return err
	}
	if err := it.overlay.Err(); err != nil {
		return err
	}
	return nil
}

func (it *treeOverlayIterator) Rewind() {
	it.inner.Rewind()
	it.overlay.Rewind()

	it.updateIteratorPosition()
}

func (it *treeOverlayIterator) Seek(key node.Key) {
	it.inner.Seek(key)
	it.overlay.Seek(key)

	it.updateIteratorPosition()
}

func (it *treeOverlayIterator) Next() {
	if !it.overlay.Valid() || it.inner.Key().Compare(it.overlay.Key()) <= 0 {
		// Key of inner iterator is smaller or equal than the key of the overlay iterator.
		it.inner.Next()
	} else {
		// Key of inner iterator is greater than the key of the overlay iterator.
		it.overlay.Next()
	}

	it.updateIteratorPosition()
}

func (it *treeOverlayIterator) updateIteratorPosition() {
	// Skip over any dirty entries from the inner iterator.
	for it.inner.Valid() && it.tree.dirty[string(it.inner.Key())] {
		it.inner.Next()
	}

	iKey := it.inner.Key()
	oKey := it.overlay.Key()

	if it.inner.Valid() && (!it.overlay.Valid() || iKey.Compare(oKey) < 0) {
		// Key of inner iterator is smaller than the key of the overlay iterator.
		it.key = iKey
		it.value = it.inner.Value()
	} else if it.overlay.Valid() {
		// Key of overlay iterator is smaller than or equal to the key of the inner iterator.
		it.key = oKey
		it.value = it.overlay.Value()
	} else {
		// Both iterators are invalid.
		it.key = nil
		it.value = nil
	}
}

func (it *treeOverlayIterator) Key() node.Key {
	return it.key
}

func (it *treeOverlayIterator) Value() []byte {
	return it.value
}

func (it *treeOverlayIterator) GetProof() (*syncer.Proof, error) {
	panic(fmt.Errorf("tree overlay: proofs are not supported"))
}

func (it *treeOverlayIterator) GetProofBuilder() *syncer.ProofBuilder {
	panic(fmt.Errorf("tree overlay: proofs are not supported"))
}

func (it *treeOverlayIterator) Close() {
	it.inner.Close()
	it.overlay.Close()

	it.key = nil
	it.value = nil
	it.tree = nil
}
