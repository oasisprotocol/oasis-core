package urkel

import (
	"context"
	"errors"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

var errClosed = errors.New("iterator: use of closed iterator")

// Iterator is an Urkel tree iterator.
//
// Iterators are not safe for concurrent use.
type Iterator interface {
	// Valid checks whether the iterator points to a valid item.
	Valid() bool
	// Err returns an error in case iteration failed due to an error.
	Err() error
	// Rewind moves the iterator to the first key in the tree.
	Rewind()
	// Seek moves the iterator either at the given key or at the next larger
	// key.
	Seek(node.Key)
	// Next advances the iterator to the next key.
	Next()
	// Key returns the key under the iterator.
	Key() node.Key
	// Value returns the value under the iterator.
	Value() []byte
	// Close releases resources associated with the iterator.
	//
	// Not calling this method leads to memory leaks.
	Close()
}

type visitState uint8

const (
	visitBefore visitState = iota
	visitAt
	visitAtLeft
	visitAfter
)

type pathAtom struct {
	path     node.Key
	ptr      *node.Pointer
	bitDepth node.Depth
	state    visitState
}

type treeIterator struct {
	ctx   context.Context
	tree  *Tree
	err   error
	pos   []pathAtom
	key   node.Key
	value []byte
}

// NewIterator creates a new iterator over the given tree.
func NewIterator(ctx context.Context, tree *Tree) Iterator {
	return &treeIterator{
		ctx:  ctx,
		tree: tree,
	}
}

func (it *treeIterator) Valid() bool {
	return it.key != nil
}

func (it *treeIterator) Err() error {
	return it.err
}

func (it *treeIterator) Rewind() {
	it.Seek(node.Key{})
}

func (it *treeIterator) reset() {
	it.pos = nil
	it.key = nil
	it.value = nil
}

func (it *treeIterator) setError(err error) {
	it.err = err
	it.reset()
}

func (it *treeIterator) Seek(key node.Key) {
	if it.err != nil {
		return
	}

	it.reset()
	err := it.doNext(it.tree.cache.pendingRoot, 0, node.Key{}, key, visitBefore)
	if err != nil {
		// Make sure to invalidate the iterator on error.
		it.setError(err)
	}
}

func (it *treeIterator) Next() {
	if it.err != nil {
		return
	}

	for len(it.pos) > 0 {
		// Start where we left off.
		atom := it.pos[0]
		remainder := it.pos[1:]

		// Try to proceed with the current node. If we don't succeed, proceed to the
		// next node.
		key := it.key
		it.reset()
		err := it.doNext(atom.ptr, atom.bitDepth, atom.path, key, atom.state)
		if err != nil {
			it.setError(err)
			return
		}
		if it.key != nil {
			// Key has been found.
			it.pos = append(it.pos, remainder...)
			return
		}

		it.key = key
		it.pos = remainder
	}

	// We have reached the end of the tree, make sure everything is reset.
	it.key = nil
	it.value = nil
}

func (it *treeIterator) doNext(ptr *node.Pointer, bitDepth node.Depth, path node.Key, key node.Key, state visitState) error {
	// TODO: Hint the remote end that we are iterating (ekiden#1983).
	nd, err := it.tree.cache.derefNodePtr(it.ctx, node.ID{Path: path, BitDepth: bitDepth}, ptr, key)
	if err != nil {
		return err
	}

	switch n := nd.(type) {
	case nil:
		// Reached a nil node, there is nothing here.
		return nil
	case *node.InternalNode:
		// Internal node.
		bitLength := bitDepth + n.LabelBitLength

		// Does lookup key end here? Look into LeafNode.
		if (state == visitBefore && key.BitLength() <= bitLength) || state == visitAt {
			if state == visitBefore {
				err := it.doNext(n.LeafNode, bitLength, path, key, visitBefore)
				if err != nil {
					return err
				}
				if it.key != nil {
					// Key has been found.
					it.pos = append(it.pos, pathAtom{state: visitAt, ptr: ptr, bitDepth: bitDepth, path: path})
					return nil
				}
			}
			// Key has not been found, continue with search for next key.
			key = key.AppendBit(bitLength, false)
		}

		if state == visitBefore {
			state = visitAt
		}

		newPath := path.Merge(bitDepth, n.Label, n.LabelBitLength)

		// Continue recursively based on a bit value.
		if (state == visitAt && !key.GetBit(bitLength)) || state == visitAtLeft {
			if state == visitAt {
				err := it.doNext(n.Left, bitLength, newPath.AppendBit(bitLength, false), key, visitBefore)
				if err != nil {
					return err
				}
				if it.key != nil {
					// Key has been found.
					it.pos = append(it.pos, pathAtom{state: visitAtLeft, ptr: ptr, bitDepth: bitDepth, path: path})
					return nil
				}
			}
			// Key has not been found, continue with search for next key.
			key, _ = key.Split(bitLength, key.BitLength())
			key = key.AppendBit(bitLength, true)
		}

		if state == visitAt || state == visitAtLeft {
			err := it.doNext(n.Right, bitLength, newPath.AppendBit(bitLength, true), key, visitBefore)
			if err != nil {
				return err
			}
			if it.key != nil {
				// Key has been found.
				it.pos = append(it.pos, pathAtom{state: visitAfter, ptr: ptr, bitDepth: bitDepth, path: path})
			}
		}
	case *node.LeafNode:
		// Reached a leaf node.
		if n.Key.Compare(key) >= 0 {
			it.key = n.Key

			// Fetch value. It currently doesn't make sense to make this lazy
			// as the leaf nodes contain the full values.
			var err error
			it.value, err = it.tree.cache.derefValue(it.ctx, n.Value)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (it *treeIterator) Key() node.Key {
	return it.key
}

func (it *treeIterator) Value() []byte {
	return it.value
}

func (it *treeIterator) Close() {
	it.reset()
	it.ctx = nil
	it.tree = nil
	it.err = errClosed
}
