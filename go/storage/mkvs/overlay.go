package mkvs

import (
	"context"
	"fmt"

	"github.com/tidwall/btree"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

var _ OverlayTree = (*treeOverlay)(nil)

type treeOverlay struct {
	inner   KeyValueTree
	overlay btree.Map[string, []byte]

	dirty map[string]bool
}

// NewOverlay creates a new key-value tree overlay that holds all updates in memory and only commits
// them if requested. This can be used to create snapshots that can be discarded.
//
// While updates (inserts, removes) are stored in the overlay, reads are not cached in the overlay
// as the inner tree has its own cache and double caching makes less sense.
//
// The overlay is not safe for concurrent use.
func NewOverlay(inner KeyValueTree) OverlayTree {
	return &treeOverlay{
		inner: inner,
		dirty: make(map[string]bool),
	}
}

// Implements KeyValueTree.
func (o *treeOverlay) Insert(ctx context.Context, key, value []byte) error {
	o.overlay.Set(string(key), value)
	o.dirty[string(key)] = true
	return nil
}

// Implements KeyValueTree.
func (o *treeOverlay) Get(ctx context.Context, key []byte) ([]byte, error) {
	// For dirty values, check the overlay.
	if o.dirty[string(key)] {
		value, _ := o.overlay.Get(string(key))
		return value, nil
	}

	// Otherwise fetch from inner tree.
	return o.inner.Get(ctx, key)
}

// Implements KeyValueTree.
func (o *treeOverlay) RemoveExisting(ctx context.Context, key []byte) ([]byte, error) {
	// For dirty values, remove from the overlay.
	if o.dirty[string(key)] {
		value, _ := o.overlay.Delete(string(key))
		return value, nil
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
	o.overlay.Delete(string(key))
	return nil
}

// Implements KeyValueTree.
func (o *treeOverlay) NewIterator(ctx context.Context, options ...IteratorOption) Iterator {
	return &treeOverlayIterator{
		tree:    o,
		inner:   o.inner.NewIterator(ctx, options...),
		overlay: o.overlay.Iter(),
	}
}

// Implements OverlayTree.
func (o *treeOverlay) Copy(inner KeyValueTree) OverlayTree {
	if inner == nil {
		inner = o.inner
	}
	o2 := &treeOverlay{
		inner: inner,
		dirty: make(map[string]bool),
	}
	for k := range o.dirty {
		o2.dirty[k] = true
	}
	overlay := o.overlay.Copy()
	o2.overlay = *overlay
	return o2
}

// Implements OverlayTree.
func (o *treeOverlay) Commit(ctx context.Context) (KeyValueTree, error) {
	// Insert all items present in the overlay.
	it := o.overlay.Iter()
	for ok := it.First(); ok; ok = it.Next() {
		if err := o.inner.Insert(ctx, []byte(it.Key()), it.Value()); err != nil {
			return nil, err
		}
		delete(o.dirty, it.Key())
	}

	// Any remaining dirty items must have been removed.
	for key := range o.dirty {
		if err := o.inner.Remove(ctx, []byte(key)); err != nil {
			return nil, err
		}
	}

	o.dirty = make(map[string]bool)
	o.overlay.Clear()

	return o.inner, nil
}

// Implements ClosableTree.
func (o *treeOverlay) Close() {
	if o.inner == nil {
		return
	}

	o.overlay.Clear()

	o.inner = nil
	o.dirty = nil
}

type treeOverlayIterator struct {
	tree *treeOverlay

	inner        Iterator
	overlay      btree.MapIter[string, []byte]
	overlayValid bool

	key   node.Key
	value []byte
}

func (it *treeOverlayIterator) Valid() bool {
	// If either iterator is valid, the merged iterator is valid.
	return it.inner.Valid() || it.overlayValid
}

func (it *treeOverlayIterator) Err() error {
	return it.inner.Err()
}

func (it *treeOverlayIterator) Rewind() {
	it.inner.Rewind()
	it.overlayValid = it.overlay.First()

	it.updateIteratorPosition()
}

func (it *treeOverlayIterator) Seek(key node.Key) {
	it.inner.Seek(key)
	it.overlayValid = it.overlay.Seek(string(key))

	it.updateIteratorPosition()
}

func (it *treeOverlayIterator) Next() {
	if !it.overlayValid || (it.inner.Valid() && it.inner.Key().Compare(node.Key(it.overlay.Key())) <= 0) {
		// Key of inner iterator is smaller or equal than the key of the overlay iterator.
		it.inner.Next()
	} else {
		// Key of inner iterator is greater than the key of the overlay iterator.
		it.overlayValid = it.overlay.Next()
	}

	it.updateIteratorPosition()
}

func (it *treeOverlayIterator) updateIteratorPosition() {
	// Skip over any dirty entries from the inner iterator.
	for it.inner.Valid() && it.tree.dirty[string(it.inner.Key())] {
		it.inner.Next()
	}

	iKey := it.inner.Key()
	oKey := node.Key(it.overlay.Key())

	if it.inner.Valid() && (!it.overlayValid || iKey.Compare(oKey) < 0) {
		// Key of inner iterator is smaller than the key of the overlay iterator.
		it.key = iKey
		it.value = it.inner.Value()
	} else if it.overlayValid {
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

	it.key = nil
	it.value = nil
	it.tree = nil
}

type treeOverlayWrapper struct {
	Tree
}

// Implements OverlayTree.
func (tow *treeOverlayWrapper) Copy(inner KeyValueTree) OverlayTree {
	panic("copy not supported")
}

// Implements OverlayTree.
func (tow *treeOverlayWrapper) Commit(ctx context.Context) (KeyValueTree, error) {
	return tow.Tree, nil
}

// NewOverlayWrapper wraps an existing tree so it can behave as an overlay tree without any actual
// overlay overhead.
func NewOverlayWrapper(inner Tree) OverlayTree {
	return &treeOverlayWrapper{inner}
}
