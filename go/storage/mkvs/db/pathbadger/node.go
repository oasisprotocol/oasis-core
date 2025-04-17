package pathbadger

import (
	"encoding/binary"
	"fmt"

	"github.com/dgraph-io/badger/v4"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

// Database node serialization kind constants.
const (
	kindLeaf              = 1
	kindInternalWithLeft  = 2
	kindInternalWithRight = 3
	kindInternalWithBoth  = 4
)

const (
	// versionInvalid is an invalid node version.
	versionInvalid = 0xffffffffffffffff

	// indexRootNode is the index of the root node.
	indexRootNode = 0
	// indexInvalid is an invalid node index.
	indexInvalid = 0xffffffff
)

// Implements api.NodeDB.
func (d *badgerNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		return nil, fmt.Errorf("mkvs/pathbadger: invalid node pointer")
	}
	if err := d.sanityCheckNamespace(&root.Namespace); err != nil {
		return nil, err
	}
	// If the version is earlier than the earliest version, we don't have the node (it was pruned).
	// Note that the key can still be present in the database until it gets compacted.
	if root.Version < d.meta.getEarliestVersion() {
		return nil, api.ErrNodeNotFound
	}

	tx := d.db.NewTransactionAt(versionToTs(root.Version), false)
	defer tx.Discard()

	// Check if the root actually exists.
	if err := d.checkRootExists(tx, root); err != nil {
		return nil, err
	}
	rootHash := api.TypedHashFromRoot(root)

	var (
		item  *badger.Item
		dbKey []byte
		err   error
	)
	switch {
	case ptr.Hash.Equal(&root.Hash):
		// Requesting the root node which is special.
		item, err = tx.Get(rootNodeKeyFmt.Encode(root.Version, &rootHash))

		ptr.DBInternal = &dbPtr{
			version: root.Version,
			index:   indexRootNode,
		}
	default:
		// Requesting a different node, it must have come from us.
		iptr, ok := ptr.DBInternal.(*dbPtr)
		if !ok {
			return nil, fmt.Errorf("mkvs/pathbadger: invalid node pointer not from this db")
		}

		// Determine sequence number for the root. All finalized roots use a seqNo of zero.
		seqNo, _ := d.meta.getPendingRootSeqNo(root.Version, rootHash)

		dbKey = iptr.dbKey()
		if seqNo == 0 {
			item, err = tx.Get(finalizedNodeKeyFmt.Encode(byte(root.Type), dbKey))
		} else {
			item, err = tx.Get(pendingNodeKeyFmt.Encode(root.Version, byte(root.Type), seqNo, dbKey))
			if err == badger.ErrKeyNotFound {
				// The node may be finalized, need to check the finalized version too.
				item, err = tx.Get(finalizedNodeKeyFmt.Encode(byte(root.Type), dbKey))
			}
		}
	}

	switch err {
	case nil:
	case badger.ErrKeyNotFound:
		return nil, api.ErrNodeNotFound
	default:
		d.logger.Error("failed to Get node from backing store",
			"err", err,
		)
		return nil, fmt.Errorf("mkvs/pathbadger: failed to Get node from backing store: %w", err)
	}

	var n node.Node
	if err = item.Value(func(val []byte) error {
		var vErr error
		n, vErr = nodeFromDb(val)
		return vErr
	}); err != nil {
		d.logger.Error("failed to unmarshal node",
			"err", err,
		)
		return nil, fmt.Errorf("mkvs/pathbadger: failed to unmarshal node: %w", err)
	}

	return n, nil
}

type badgerSubtree struct {
	batch *badgerBatch
}

// Implements api.Subtree.
func (s *badgerSubtree) VisitCleanNode(depth node.Depth, ptr *node.Pointer, parent *node.Pointer) error {
	var needsPutNode bool
	if parent == nil && ptr.DBInternal == nil {
		// If this is a clean root node, don't do anything as it seems the root has not changed.
		// This is a special case because roots are only resolved if any modification or lookup is
		// performed on them, but if nothing has changed, the root pointer may be unresolved.
		return nil
	}
	iptr := ptr.DBInternal.(*dbPtr) // Node is clean so it must be from the database.

	// Check if the node's "root node status" has changed. In this case, we need to reset the index.
	wasRootNode := iptr.isRoot()
	isRootNode := parent == nil
	if wasRootNode != isRootNode {
		ptr.DBInternal = nil
		needsPutNode = true

		// Node was not a root node before, but now it has become one. It needs to be removed as it
		// will otherwise remain in storage for no good reason.
		if isRootNode {
			s.batch.updatedNodes = append(s.batch.updatedNodes, updatedNode{
				Removed: true,
				Key:     iptr.dbKey(),
			})
		}
	}

	// Check if the node was invalid before but should now be a standalone node.
	var isInvalid bool
	wasInvalid := iptr.isInvalid()
	if parent != nil {
		if intNode, ok := parent.Node.(*node.InternalNode); ok {
			isInvalid = intNode.LeafNode == ptr // If we are an internal leaf node.
		}
	}
	if wasInvalid && !isInvalid {
		ptr.DBInternal = nil
		needsPutNode = true

	}

	if err := s.refreshDbPtr(ptr, parent); err != nil {
		return err
	}

	if needsPutNode {
		return s.PutNode(depth, ptr)
	}
	return nil
}

// Implements api.Subtree.
func (s *badgerSubtree) VisitDirtyNode(_ node.Depth, ptr *node.Pointer, parent *node.Pointer) error {
	return s.refreshDbPtr(ptr, parent)
}

// refreshDbPtr recomputes the data for the internal database pointer.
func (s *badgerSubtree) refreshDbPtr(ptr *node.Pointer, parent *node.Pointer) error {
	if ptr.DBInternal == nil {
		// Assign new index if none exists.
		var index uint32
		switch parent {
		case nil:
			// Root node.
			index = indexRootNode
		default:
			// Non-root node, assign new index.
			index = s.batch.lastIndex.Add(1)
		}

		ptr.DBInternal = &dbPtr{
			version: s.batch.version,
			index:   index,
		}
	}

	// If this is a multipart insert, the node may already exist. In this case, we need to fetch it
	// from the database and update our pointers.
	s.batch.db.metaUpdateLock.Lock()
	defer s.batch.db.metaUpdateLock.Unlock()

	multipartVersion := s.batch.db.multipartVersion
	if multipartVersion == multipartVersionNone {
		return nil
	}

	dbKey := ptr.DBInternal.(*dbPtr).dbKey()
	if parent == nil {
		multiMeta := s.batch.db.multipartMeta[uint8(s.batch.oldRoot.Type)]
		if multiMeta.root != nil {
			dbKey = rootNodeKeyFmt.Encode(multipartVersion, multiMeta.root)
		}
	} else {
		dbKey = s.deriveNodeDbKey(dbKey)
	}

	return s.multipartMergeWithExisting(dbKey, ptr)
}

// Implements api.Subtree.
func (s *badgerSubtree) PutNode(_ node.Depth, ptr *node.Pointer) error {
	iptr, ok := ptr.DBInternal.(*dbPtr)
	if !ok {
		return fmt.Errorf("mkvs/pathbadger: bad internal pointer")
	}

	// Skip nodes that should not be stored separately.
	if iptr.isInvalid() {
		return nil
	}

	// Determine the correct database key based on the batch sequence number.
	key, value, err := nodeToDb(ptr)
	if err != nil {
		return err
	}

	// Root node is special.
	if iptr.isRoot() {
		s.batch.newRootValue = value
		return nil
	}

	s.batch.updatedNodes = append(s.batch.updatedNodes, updatedNode{
		Key: key,
	})

	dbKey := s.deriveNodeDbKey(key)
	if s.batch.seqNo != 0 {
		// Need to commit at tsMetadata so this can be garbage-collected upon finalization.
		return s.batch.batMeta.Set(dbKey, value)
	}
	return s.batch.bat.Set(dbKey, value)
}

func (s *badgerSubtree) deriveNodeDbKey(key []byte) []byte {
	var dbKey []byte
	rootType := byte(s.batch.oldRoot.Type)
	seqNo := s.batch.seqNo
	if seqNo == 0 {
		dbKey = finalizedNodeKeyFmt.Encode(rootType, key)
	} else {
		dbKey = pendingNodeKeyFmt.Encode(s.batch.version, rootType, seqNo, key)
	}
	return dbKey
}

// nodeToDb serializes a node to an internal format for the database.
func nodeToDb(ptr *node.Pointer) ([]byte, []byte, error) {
	iptr := ptr.DBInternal.(*dbPtr)
	key := iptr.dbKey()

	switch n := ptr.Node.(type) {
	case *node.LeafNode:
		leafKey, _ := n.Key.MarshalBinary()
		value := append([]byte{kindLeaf}, leafKey...)
		value = append(value, n.Value...) // Copy value.
		return key, value, nil
	case *node.InternalNode:
		var kind uint8
		switch {
		case n.Left != nil && n.Right != nil:
			kind = kindInternalWithBoth
		case n.Left != nil:
			kind = kindInternalWithLeft
		case n.Right != nil:
			kind = kindInternalWithRight
		}

		value := []byte{kind}
		label, _ := n.Label.MarshalBinary()
		value = append(value, label...)
		value = append(value, n.LabelBitLength.MarshalBinary()...)

		if n.Left != nil {
			value = append(value, ptrToDb(n.Left)...)
		}
		if n.Right != nil {
			value = append(value, ptrToDb(n.Right)...)
		}
		if n.LeafNode != nil {
			ln := n.LeafNode.Node.(*node.LeafNode)
			leafKey, _ := ln.Key.MarshalBinary()
			value = append(value, leafKey...)
			value = append(value, ln.Value...)
		}
		return key, value, nil
	default:
		return nil, nil, fmt.Errorf("mkvs: unsupported node kind '%T' (db corruption?)", ptr.Node)
	}
}

func leafFromDb(value []byte) ([]byte, []byte, error) {
	rawNode, err := nodeFromDb(value)
	if err != nil {
		return nil, nil, err
	}

	switch n := rawNode.(type) {
	case *node.LeafNode:
		return n.Key, n.Value, nil
	case *node.InternalNode:
		if n.LeafNode != nil {
			ln := n.LeafNode.Node.(*node.LeafNode)
			return ln.Key, ln.Value, nil
		}
	default:
	}
	return nil, nil, nil
}

// nodeFromDb deserializes a node from its internal database format.
func nodeFromDb(value []byte) (node.Node, error) {
	if len(value) < 2 {
		return nil, fmt.Errorf("malformed node (db corruption?)")
	}

	pos := 1

	// Format: [kind] <data...>
	switch kind := value[0]; kind {
	case kindLeaf:
		// Format: [key] [value]
		var key node.Key
		size, err := key.SizedUnmarshalBinary(value[pos:])
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal key: %w", err)
		}
		pos += size

		n := node.LeafNode{
			Clean: true,
			Key:   key,
			Value: append([]byte{}, value[pos:]...), // Copy value.
		}
		n.UpdateHash()

		return &n, nil
	case kindInternalWithLeft, kindInternalWithRight, kindInternalWithBoth:
		// Format: [label] [labelBitLength] [leftPtr] [rightPtr] [key] [value]
		n := node.InternalNode{
			Clean: true,
		}

		// Label of the node's incoming edge is the suffix.
		size, err := n.Label.SizedUnmarshalBinary(value[pos:])
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal label size: %w", err)
		}
		pos += size
		size, err = n.LabelBitLength.UnmarshalBinary(value[pos:])
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal label bit length: %w", err)
		}
		pos += size

		// Left pointer.
		if kind == kindInternalWithLeft || kind == kindInternalWithBoth {
			size, ptr, err := ptrFromDb(value[pos:])
			if err != nil {
				return nil, err
			}
			pos += size
			n.Left = ptr
		}

		// Right pointer.
		if kind == kindInternalWithRight || kind == kindInternalWithBoth {
			size, ptr, err := ptrFromDb(value[pos:])
			if err != nil {
				return nil, err
			}
			pos += size
			n.Right = ptr
		}

		// Optional value of leaf node if there is anything left.
		if len(value) > pos {
			leaf := node.LeafNode{
				Clean: true,
			}
			size, err := leaf.Key.SizedUnmarshalBinary(value[pos:])
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal leaf node size: %w", err)
			}
			pos += size

			leaf.Value = append([]byte{}, value[pos:]...) // Copy value.
			leaf.UpdateHash()

			n.LeafNode = &node.Pointer{
				Clean:      true,
				Hash:       leaf.Hash,
				Node:       &leaf,
				DBInternal: newInvalidDbPtr(), // Not standalone.
			}
		}

		n.UpdateHash()

		return &n, nil
	default:
		return nil, fmt.Errorf("mkvs: unsupported node kind '%X' (db corruption?)", kind)
	}
}

// ptrToDb serializes a MKVS pointer into an internal database representation.
func ptrToDb(ptr *node.Pointer) []byte {
	iptr := ptr.DBInternal.(*dbPtr)
	if iptr.isInvalid() {
		panic("mkvs/pathbadger: attempted to serialize invalid internal pointer")
	}
	if ptr.Hash.IsEmpty() {
		panic("mkvs/pathbadger: attempted to serialize an empty pointer")
	}

	h, _ := ptr.Hash.MarshalBinary()
	data := append(h, encodeNodeKey(iptr.version, iptr.index)...)

	return data
}

// ptrFromDb deserializes a pointer from internal database representation.
func ptrFromDb(data []byte) (int, *node.Pointer, error) {
	// Format: [hash] [version] [index]

	// Validate data size.
	if len(data) < hash.Size+8+4 {
		return 0, nil, fmt.Errorf("malformed pointer (not enough bytes)")
	}

	var (
		h   hash.Hash
		err error
	)
	if err = h.UnmarshalBinary(data[:hash.Size]); err != nil {
		return 0, nil, fmt.Errorf("failed to unmarshal hash: %w", err)
	}
	if h.IsEmpty() {
		// Empty hashes are not allowed in serialized form.
		return 0, nil, fmt.Errorf("serialized empty hash encountered in pointer (db corruption?)")
	}
	pos := hash.Size

	version := binary.BigEndian.Uint64(data[pos:])
	pos += 8
	index := binary.BigEndian.Uint32(data[pos:])
	pos += 4

	ptr := &node.Pointer{
		Clean: true,
		Hash:  h,
		DBInternal: &dbPtr{
			version: version,
			index:   index,
		},
	}
	return pos, ptr, nil
}

func encodeVersionKey(version uint64) []byte {
	var rawVersion [8]byte
	binary.BigEndian.PutUint64(rawVersion[:], version)
	return rawVersion[:]
}

func encodeIndexKey(index uint32) []byte {
	var rawIndex [4]byte
	binary.BigEndian.PutUint32(rawIndex[:], index)
	return rawIndex[:]
}

func encodeNodeKey(version uint64, index uint32) []byte {
	data := append([]byte{}, encodeVersionKey(version)...)
	data = append(data, encodeIndexKey(index)...)
	return data
}

// dbPtr contains internal metadata needed for pointer resolution.
type dbPtr struct {
	version uint64
	index   uint32
}

// newInvalidDbPtr constructs an invalid dbPtr.
func newInvalidDbPtr() *dbPtr {
	return &dbPtr{
		version: versionInvalid,
		index:   indexInvalid,
	}
}

// isRoot returns true iff this dbPtr represents the root node based on its index.
func (p *dbPtr) isRoot() bool {
	return p.index == indexRootNode
}

// isInvalid returns true iff this dbPtr represents an invalid node. Note that this is different
// from a dirty node (which just means a node that was locally modified) as an invalid pointer is
// used for nodes which should never be stored as stand-alone nodes.
func (p *dbPtr) isInvalid() bool {
	return p.version == versionInvalid && p.index == indexInvalid
}

// dbKey returns the database key to use to resolve this pointer.
func (p *dbPtr) dbKey() []byte {
	return encodeNodeKey(p.version, p.index)
}

// Implements node.DBPointer.
func (p *dbPtr) SetDirty() {
	p.version = versionInvalid
	p.index = indexInvalid
}

// Implements node.DBPointer.
func (p *dbPtr) Clone() node.DBPointer {
	return &dbPtr{
		version: p.version,
		index:   p.index,
	}
}
