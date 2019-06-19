package murkdb

import (
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

// maxSubtreeAggregationDepth is the amount of subtree levels to aggregate into
// a single page. All aggregated nodes are treated as a single bigger node when
// subject to garbage collection.
const maxSubtreeAggregationDepth = 5

func (d *murkNodeDB) NewBatch() api.Batch {
	// Take the write lock (there can be only one write batch open at a time).
	d.meta.openBatch()

	return &murkdbBatch{
		db: d,
	}
}

type murkdbBatch struct {
	db *murkNodeDB

	closed bool
	root   *murkdbSubtree
}

func (b *murkdbBatch) MaybeStartSubtree(subtree api.Subtree, depth uint8, subtreeRoot *internal.Pointer) api.Subtree {
	if subtree == nil {
		if depth != 0 {
			panic("murkdb: tried to start root subtree at non-zero depth")
		}
		if b.root != nil {
			panic("murkdb: tried to start root subtree when one has already been started")
		}

		// Create a new subtree for the root node.
		st := &murkdbSubtree{
			batch:    b,
			rootPtr:  subtreeRoot,
			aggDepth: 0,
		}
		b.root = st
		return st
	}

	// If we are still in the same subtree, return it.
	st := subtree.(*murkdbSubtree)
	aggDepth := depth / maxSubtreeAggregationDepth
	if aggDepth == st.aggDepth {
		return subtree
	}

	// We need to actually start a new subtree.
	return &murkdbSubtree{
		batch:    b,
		rootPtr:  subtreeRoot,
		aggDepth: aggDepth,
	}
}

func (b *murkdbBatch) Commit(root hash.Hash) error {
	// All pages have been written -- update metadata.
	b.db.meta.commitBatchLocked(root, pointerToOffset(b.root.rootPtr))
	b.closed = true

	return nil
}

func (b *murkdbBatch) Reset() {
	if !b.closed {
		b.db.meta.rollbackBatchLocked()
		b.closed = true
	}
}

type pendingNode struct {
	ptr *internal.Pointer

	pageNode *pageNodeHeader
	offset   uint64
}

type murkdbSubtree struct {
	batch *murkdbBatch

	rootPtr  *internal.Pointer
	aggDepth uint8

	nodeSize uint32
	dataSize uint32

	addedNodes []*pendingNode
}

func (s *murkdbSubtree) PutNode(depth uint8, ptr *internal.Pointer) error {
	if depth/maxSubtreeAggregationDepth != s.aggDepth {
		return errors.New("murkdb: tried to persist node at inconsistent depth")
	}

	switch n := ptr.Node.(type) {
	case *internal.InternalNode:
		s.nodeSize += uint32(internalPageNodeSize)
	case *internal.LeafNode:
		s.nodeSize += uint32(leafPageNodeSize)
		s.dataSize += uint32(len(n.Key[:])) + uint32(len(n.Value.Value))
	}
	s.addedNodes = append(s.addedNodes, &pendingNode{
		ptr:      ptr,
		pageNode: nil,
	})
	return nil
}

func (s *murkdbSubtree) copyExistingPtr(depth uint8, offset uint64, ptr *internal.Pointer) error {
	// Only copy nodes that fall into the same aggregated depth.
	if depth/maxSubtreeAggregationDepth != s.aggDepth {
		return nil
	}

	// Dereference pointer to get the target node.
	pn, err := s.batch.db.tree.dereference(offset)
	if err != nil {
		return err
	}

	switch pn.kind {
	case pageNodeKindInternal:
		n := pn.internalNode()

		// Check if we need to add any existing children.
		if n.leftOffset != invalidOffset {
			if err := s.copyExistingPtr(depth+1, n.leftOffset, nil); err != nil {
				return err
			}
		}
		if n.rightOffset != invalidOffset {
			if err := s.copyExistingPtr(depth+1, n.rightOffset, nil); err != nil {
				return err
			}
		}

		s.nodeSize += uint32(internalPageNodeSize)
	case pageNodeKindLeaf:
		n := pn.leafNode()

		s.nodeSize += uint32(leafPageNodeSize)
		s.dataSize += uint32(n.keySize) + uint32(n.valueSize)
	default:
		return ErrCorruptedDb
	}

	// Record copied nodes.
	s.addedNodes = append(s.addedNodes, &pendingNode{
		ptr:      ptr,
		pageNode: pn,
		offset:   offset,
	})

	return nil
}

func (s *murkdbSubtree) VisitCleanNode(depth uint8, ptr *internal.Pointer) error {
	if depth/maxSubtreeAggregationDepth != s.aggDepth {
		return errors.New("murkdb: tried to visit clean node at inconsistent depth")
	}

	return s.copyExistingPtr(depth, pointerToOffset(ptr), ptr)
}

func (s *murkdbSubtree) Commit() error {
	if s.nodeSize == 0 {
		return nil
	}

	// Mark previous page (if any) for garbage collection.
	if s.rootPtr.DBInternal != nil {
		// TODO: After we have garbage collection (#1759), the whole previous page can be
		//       marked as eligible for garbage collection after this one is committed.
	}

	// Compute how many pages we need to allocate.
	ps := uint32(s.batch.db.tree.pageSize)
	pages := int((uint32(pageHeaderSize) + s.nodeSize + s.dataSize + ps - 1) / ps)

	// Allocate pages for the subtree.
	page, err := s.batch.db.meta.allocateLocked(pages)
	if err != nil {
		return err
	}
	page.kind = pageKindMKVS

	// Populate the page(s).
	updatedOffsets := make(map[uint64]uint64)
	pageOffset := page.id * uint64(ps)
	offset := 0
	dataOffset := s.nodeSize
	for _, pn := range s.addedNodes {
		// Compute new offset.
		newOffset := pageOffset + uint64(pageHeaderSize+offset)

		if pn.pageNode == nil {
			// Copy data from node.
			switch n := pn.ptr.Node.(type) {
			case *internal.InternalNode:
				intNode := page.internalNodeAt(uintptr(offset))
				intNode.kind = pageNodeKindInternal

				if n.Left != nil {
					intNode.leftHash = n.Left.Hash
					intNode.leftOffset = pointerToOffset(n.Left)
				} else {
					intNode.leftHash.Empty()
					intNode.leftOffset = invalidOffset
				}
				if n.Right != nil {
					intNode.rightHash = n.Right.Hash
					intNode.rightOffset = pointerToOffset(n.Right)
				} else {
					intNode.rightHash.Empty()
					intNode.rightOffset = invalidOffset
				}

				offset += internalPageNodeSize
			case *internal.LeafNode:
				leafNode := page.leafNodeAt(uintptr(offset))
				leafNode.kind = pageNodeKindLeaf
				// Key/value offset is relative to the leaf node.
				leafNode.offset = dataOffset - uint32(offset)
				leafNode.keySize = uint32(len(n.Key[:]))
				leafNode.valueSize = uint32(len(n.Value.Value))
				offset += leafPageNodeSize

				// Copy key/value.
				copy(leafNode.key(), n.Key[:])
				copy(leafNode.value(), n.Value.Value)
				dataOffset += leafNode.keySize + leafNode.valueSize
			}
		} else {
			updatedOffsets[pn.offset] = newOffset

			// Copy data from existing page node.
			switch pn.pageNode.kind {
			case pageNodeKindInternal:
				src := pn.pageNode.internalNode()

				var ok bool
				intNode := page.internalNodeAt(uintptr(offset))
				intNode.kind = pageNodeKindInternal
				if src.leftOffset != invalidOffset {
					intNode.leftHash = src.leftHash
					// If the offset does not exist, it must point to a previous page that
					// has not changed (if it changed then this subtree would not be clean).
					if intNode.leftOffset, ok = updatedOffsets[src.leftOffset]; !ok {
						intNode.leftOffset = src.leftOffset
					}
				} else {
					intNode.leftHash.Empty()
					intNode.leftOffset = invalidOffset
				}
				if src.rightOffset != invalidOffset {
					intNode.rightHash = src.rightHash
					// If the offset does not exist, it must point to a previous page that
					// has not changed (if it changed then this subtree would not be clean).
					if intNode.rightOffset, ok = updatedOffsets[src.rightOffset]; !ok {
						intNode.rightOffset = src.rightOffset
					}
				} else {
					intNode.rightHash.Empty()
					intNode.rightOffset = invalidOffset
				}
				offset += internalPageNodeSize
			case pageNodeKindLeaf:
				src := pn.pageNode.leafNode()

				leafNode := page.leafNodeAt(uintptr(offset))
				leafNode.kind = pageNodeKindLeaf
				// Key/value offset is relative to the leaf node.
				leafNode.offset = dataOffset - uint32(offset)
				leafNode.keySize = src.keySize
				leafNode.valueSize = src.valueSize
				offset += leafPageNodeSize

				// Copy key/value.
				copy(leafNode.key(), src.key())
				copy(leafNode.value(), src.value())
				dataOffset += leafNode.keySize + leafNode.valueSize
			default:
				return ErrCorruptedDb
			}
		}

		// Update any internal offsets.
		if pn.ptr != nil {
			pn.ptr.DBInternal = newOffset
		}
	}
	updatedOffsets = nil

	// Write to disk.
	if err := s.batch.db.tree.write(page); err != nil {
		return err
	}

	s.nodeSize = 0
	s.dataSize = 0
	s.addedNodes = nil

	return nil
}
