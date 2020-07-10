package mkvs

import (
	"context"
	"errors"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

var errClosed = errors.New("iterator: use of closed iterator")

// Implements syncer.ReadSyncer.
func (t *tree) SyncIterate(ctx context.Context, request *syncer.IterateRequest) (*syncer.ProofResponse, error) {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return nil, ErrClosed
	}
	if !request.Tree.Root.Equal(&t.cache.syncRoot) {
		return nil, syncer.ErrInvalidRoot
	}
	if !t.cache.pendingRoot.IsClean() {
		return nil, syncer.ErrDirtyRoot
	}

	// Create an iterator which generates proofs. Always anchor the proof at the
	// root as an iterator may encompass many subtrees. Make sure to propagate
	// prefetching to any upstream remote syncers.
	it := t.NewIterator(ctx,
		WithProof(request.Tree.Root.Hash),
		IteratorPrefetch(request.Prefetch),
	)
	defer it.Close()

	it.Seek(request.Key)
	if it.Err() != nil {
		return nil, it.Err()
	}
	for i := 0; it.Valid() && i < int(request.Prefetch); i++ {
		it.Next()
	}
	if it.Err() != nil {
		return nil, it.Err()
	}

	// Retrieve the proof for the items iterated over.
	proof, err := it.GetProof()
	if err != nil {
		return nil, err
	}

	return &syncer.ProofResponse{
		Proof: *proof,
	}, nil
}

func (t *tree) newFetcherSyncIterate(key node.Key, prefetch uint16) readSyncFetcher {
	return func(ctx context.Context, ptr *node.Pointer, rs syncer.ReadSyncer) (*syncer.Proof, error) {
		rsp, err := rs.SyncIterate(ctx, &syncer.IterateRequest{
			Tree: syncer.TreeID{
				Root:     t.cache.syncRoot,
				Position: ptr.Hash,
			},
			Key:      key,
			Prefetch: prefetch,
		})
		if err != nil {
			return nil, err
		}
		return &rsp.Proof, nil
	}
}

// Iterator is a tree iterator.
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
	// GetProof builds a proof for all items iterated over by the iterator.
	//
	// You must initialize the iterator with a WithProof option, otherwise
	// calling this method will panic.
	GetProof() (*syncer.Proof, error)
	// GetProofBuilder returns the proof builder associated with this iterator.
	GetProofBuilder() *syncer.ProofBuilder
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
	ctx      context.Context
	tree     *tree
	prefetch uint16
	err      error
	pos      []pathAtom
	key      node.Key
	value    []byte

	proofBuilder *syncer.ProofBuilder
}

// IteratorOption is a configuration option for a tree iterator.
type IteratorOption func(it Iterator)

// IteratorPrefetch sets the number of next elements to prefetch.
//
// If no prefetch is specified, no prefetching will be done.
func IteratorPrefetch(prefetch uint16) IteratorOption {
	return func(it Iterator) {
		it.(*treeIterator).prefetch = prefetch
	}
}

// WithProof configures the iterator for generating proofs of all
// visited nodes.
func WithProof(root hash.Hash) IteratorOption {
	return func(it Iterator) {
		it.(*treeIterator).proofBuilder = syncer.NewProofBuilder(root)
	}
}

func newTreeIterator(ctx context.Context, tree *tree, options ...IteratorOption) Iterator {
	it := &treeIterator{
		ctx:  ctx,
		tree: tree,
	}

	for _, v := range options {
		v(it)
	}
	return it
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

		// Remember where the path from root to target node ends (will end).
		it.tree.cache.markPosition()
		for _, a := range remainder {
			it.tree.cache.useNode(a.ptr)
		}

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

func (it *treeIterator) doNext(ptr *node.Pointer, bitDepth node.Depth, path, key node.Key, state visitState) error { // nolint: gocyclo
	// Dereference the node, possibly making a remote request.
	nd, err := it.tree.cache.derefNodePtr(it.ctx, ptr, it.tree.newFetcherSyncIterate(key, it.prefetch))
	if err != nil {
		return err
	}

	// Include nodes in proof if we have a proof builder.
	if pb := it.proofBuilder; pb != nil && ptr != nil {
		proofRoot := pb.GetRoot()
		if pb.HasRoot() || proofRoot.Equal(&ptr.Hash) {
			pb.Include(nd)
		}
	}

	switch n := nd.(type) {
	case nil:
		// Reached a nil node, there is nothing here.
		return nil
	case *node.InternalNode:
		// Internal node.
		bitLength := bitDepth + n.LabelBitLength
		newPath := path.Merge(bitDepth, n.Label, n.LabelBitLength)

		// Check if the key is longer than the current path but lexicographically smaller. In this
		// case everything in this subtree will be larger so we need to take the first value.
		var takeFirst bool
		if bitLength > 0 && key.BitLength() >= bitLength && key.Compare(newPath) < 0 {
			takeFirst = true
		}

		// Does lookup key end here? Look into LeafNode.
		if (state == visitBefore && (key.BitLength() <= bitLength || takeFirst)) || state == visitAt {
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
			if key.BitLength() <= bitLength {
				key = key.AppendBit(bitLength, false)
			}
		}

		if state == visitBefore {
			state = visitAt
		}

		// Continue recursively based on a bit value.
		if (state == visitAt && (!key.GetBit(bitLength) || takeFirst)) || state == visitAtLeft {
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
			it.value = n.Value
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

func (it *treeIterator) GetProof() (*syncer.Proof, error) {
	if it.proofBuilder == nil {
		panic("iterator: called GetProof on an iterator without WithProof option")
	}
	return it.proofBuilder.Build(it.ctx)
}

func (it *treeIterator) GetProofBuilder() *syncer.ProofBuilder {
	return it.proofBuilder
}

func (it *treeIterator) Close() {
	it.reset()
	it.ctx = nil
	it.tree = nil
	it.err = errClosed
}
