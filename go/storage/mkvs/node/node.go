// Package node defines MKVS tree nodes.
package node

import (
	"bytes"
	"container/list"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

var (
	// ErrMalformedNode is the error when a malformed node is encountered
	// during deserialization.
	ErrMalformedNode = errors.New("mkvs: malformed node")
	// ErrMalformedKey is the error when a malformed key is encountered
	// during deserialization.
	ErrMalformedKey = errors.New("mkvs: malformed key")
)

const (
	// Prefix used in hash computations of leaf nodes.
	PrefixLeafNode byte = 0x00
	// Prefix used in hash computations of internal nodes.
	PrefixInternalNode byte = 0x01
	// Prefix used to mark a nil pointer in a subtree serialization.
	PrefixNilNode byte = 0x02

	// PointerSize is the size of a node pointer in memory.
	PointerSize = uint64(unsafe.Sizeof(Pointer{}))
	// InternalNodeSize is the minimum size of an internal node in memory.
	InternalNodeSize = uint64(unsafe.Sizeof(InternalNode{}))
	// LeafNodeSize is the minimum size of a leaf node in memory.
	LeafNodeSize = uint64(unsafe.Sizeof(LeafNode{}))

	// VersionSize is the size of the encoded version.
	VersionSize = int(unsafe.Sizeof(uint64(0)))
	// ValueLengthSize is the size of the encoded value length.
	ValueLengthSize = int(unsafe.Sizeof(uint32(0)))
)

var (
	_ encoding.BinaryMarshaler   = (*InternalNode)(nil)
	_ encoding.BinaryUnmarshaler = (*InternalNode)(nil)
	_ encoding.BinaryMarshaler   = (*LeafNode)(nil)
	_ encoding.BinaryUnmarshaler = (*LeafNode)(nil)
)

// RootType is a storage root type.
type RootType uint8

const (
	// RootTypeInvalid is an invalid/uninitialized root type.
	RootTypeInvalid RootType = 0
	// RootTypeState is the type for state storage roots.
	RootTypeState RootType = 1
	// RootTypeIO is the type for IO storage roots.
	RootTypeIO RootType = 2
)

// String returns the string representation of the storage root type.
func (r RootType) String() string {
	switch r {
	case RootTypeInvalid:
		return "invalid"
	case RootTypeState:
		return "state-root"
	case RootTypeIO:
		return "io-root"
	default:
		return fmt.Sprintf("[unknown root type: %d]", r)
	}
}

// Root is a storage root.
type Root struct {
	// Namespace is the namespace under which the root is stored.
	Namespace common.Namespace `json:"ns"`
	// Version is the monotonically increasing version number in which the root is stored.
	Version uint64 `json:"version"`
	// Type is the type of storage this root is used for.
	Type RootType `json:"root_type"`
	// Hash is the merkle root hash.
	Hash hash.Hash `json:"hash"`
}

// String returns the string representation of a storage root.
func (r Root) String() string {
	return fmt.Sprintf("<Root ns=%s version=%d type=%v hash=%s>", r.Namespace, r.Version, r.Type, r.Hash)
}

// Empty sets the storage root to an empty root.
func (r *Root) Empty() {
	var emptyNs common.Namespace
	r.Namespace = emptyNs
	r.Version = 0
	r.Hash.Empty()
}

// IsEmpty checks whether the storage root is empty.
func (r *Root) IsEmpty() bool {
	var emptyNs common.Namespace
	if !r.Namespace.Equal(&emptyNs) {
		return false
	}

	if r.Version != 0 {
		return false
	}

	return r.Hash.IsEmpty()
}

// Equal compares against another root for equality.
func (r *Root) Equal(other *Root) bool {
	if r.Type != other.Type {
		return false
	}
	if !r.Namespace.Equal(&other.Namespace) {
		return false
	}

	if r.Version != other.Version {
		return false
	}

	return r.Hash.Equal(&other.Hash)
}

// Follows checks if another root follows the given root. A root follows
// another iff the namespace matches and the version is either equal or
// exactly one higher.
//
// It is the responsibility of the caller to check if the merkle roots
// follow each other.
func (r *Root) Follows(other *Root) bool {
	if r.Type != other.Type {
		return false
	}
	if !r.Namespace.Equal(&other.Namespace) {
		return false
	}

	if r.Version != other.Version && r.Version != other.Version+1 {
		return false
	}

	return true
}

// EncodedHash returns the encoded cryptographic hash of the storage root.
func (r *Root) EncodedHash() hash.Hash {
	return hash.NewFrom(r)
}

// Pointer is a pointer to another node.
type Pointer struct {
	Clean bool
	Hash  hash.Hash
	Node  Node
	LRU   *list.Element

	// DBInternal contains NodeDB-specific internal metadata to aid
	// pointer resolution.
	DBInternal interface{}
}

// Size returns the size of this pointer in bytes.
func (p *Pointer) Size() uint64 {
	if p == nil {
		return 0
	}

	size := PointerSize
	if p.Node != nil {
		size += p.Node.Size()
	}
	return size
}

// GetHash returns the pointers's cached hash.
func (p *Pointer) GetHash() hash.Hash {
	if p == nil {
		var h hash.Hash
		h.Empty()
		return h
	}

	return p.Hash
}

// IsClean returns true if the pointer is clean.
func (p *Pointer) IsClean() bool {
	if p == nil {
		return true
	}

	return p.Clean
}

// Extract makes a copy of the pointer containing only hash references.
func (p *Pointer) Extract() *Pointer {
	if !p.IsClean() {
		panic("mkvs: extract called on dirty pointer")
	}
	return p.ExtractUnchecked()
}

// Extract makes a copy of the pointer containing only hash references
// without checking the dirty flag.
func (p *Pointer) ExtractUnchecked() *Pointer {
	if p == nil {
		return nil
	}

	return &Pointer{
		Clean: true,
		Hash:  p.Hash,
	}
}

// ExtractWithNode makes a copy of the pointer containing hash references
// and an extracted copy of the node pointed to.
func (p *Pointer) ExtractWithNode() *Pointer {
	if !p.IsClean() {
		panic("mkvs: extract with node called on dirty pointer")
	}
	return p.ExtractWithNodeUnchecked()
}

// ExtractWithNodeUnchecked makes a copy of the pointer containing hash references
// and an extracted copy of the node pointed to without checking the dirty flag.
func (p *Pointer) ExtractWithNodeUnchecked() *Pointer {
	ptr := p.ExtractUnchecked()
	if ptr == nil {
		return nil
	}

	ptr.Node = p.Node.ExtractUnchecked()
	return ptr
}

// Equal compares two pointers for equality.
func (p *Pointer) Equal(other *Pointer) bool {
	if (p == nil || other == nil) && p != other {
		return false
	}
	if p.Clean && other.Clean {
		return p.Hash.Equal(&other.Hash)
	}
	return p.Node != nil && other.Node != nil && p.Node.Equal(other.Node)
}

// Node is either an InternalNode or a LeafNode.
type Node interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler

	// IsClean returns true if the node is non-dirty.
	IsClean() bool

	// CompactMarshalBinary encodes a node into binary form without any hash
	// pointers (e.g., for proofs).
	CompactMarshalBinary() ([]byte, error)

	// GetHash returns the node's cached hash.
	GetHash() hash.Hash

	// GetCreatedVersion returns the version in which the node has been created.
	GetCreatedVersion() uint64

	// UpdateHash updates the node's cached hash by recomputing it.
	//
	// Does not mark the node as clean.
	UpdateHash()

	// Extract makes a copy of the node containing only hash references.
	Extract() Node

	// ExtractUnchecked makes a copy of the node containing only hash
	// references without checking the dirty flag.
	ExtractUnchecked() Node

	// Equal compares a node with another node.
	Equal(other Node) bool

	// Size returns the size of this pointer in bytes.
	Size() uint64
}

// InternalNode is an internal node with two children and possibly a leaf.
//
// Note that Label and LabelBitLength can only be empty iff the internal
// node is the root of the tree.
type InternalNode struct {
	// Version is the version in which the node has been created.
	Version uint64
	Hash    hash.Hash
	// Label is the label on the incoming edge.
	Label Key
	// LabelBitLength is the length of the label in bits.
	LabelBitLength Depth
	Clean          bool
	// LeafNode is for the key ending at this depth.
	LeafNode *Pointer
	Left     *Pointer
	Right    *Pointer
}

// IsClean returns true if the node is non-dirty.
func (n *InternalNode) IsClean() bool {
	return n.Clean
}

// Size returns the size of this internal node in bytes.
func (n *InternalNode) Size() uint64 {
	size := InternalNodeSize
	size += uint64(len(n.Label))
	size += n.LeafNode.Size() + n.Left.Size() + n.Right.Size()
	return size
}

// UpdateHash updates the node's cached hash by recomputing it.
//
// Does not mark the node as clean.
func (n *InternalNode) UpdateHash() {
	var version [8]byte
	binary.LittleEndian.PutUint64(version[:], n.Version)

	leafNodeHash := n.LeafNode.GetHash()
	leftHash := n.Left.GetHash()
	rightHash := n.Right.GetHash()
	labelBitLength := n.LabelBitLength.MarshalBinary()

	n.Hash.FromBytes(
		[]byte{PrefixInternalNode},
		version[:],
		labelBitLength,
		n.Label[:],
		leafNodeHash[:],
		leftHash[:],
		rightHash[:],
	)
}

// GetHash returns the node's cached hash.
func (n *InternalNode) GetHash() hash.Hash {
	return n.Hash
}

// GetCreatedVersion returns the version in which the node has been created.
func (n *InternalNode) GetCreatedVersion() uint64 {
	return n.Version
}

// Extract makes a copy of the node containing only hash references.
//
// For LeafNode, it makes a deep copy so that the parent internal node always
// ships it since we cannot address the LeafNode uniquely with NodeID (both the
// internal node and LeafNode have the same path and bit depth).
func (n *InternalNode) Extract() Node {
	if !n.Clean {
		panic("mkvs: extract called on dirty node")
	}
	return &InternalNode{
		Clean:          true,
		Version:        n.Version,
		Hash:           n.Hash,
		Label:          n.Label,
		LabelBitLength: n.LabelBitLength,
		// LeafNode is always contained in internal node.
		LeafNode: n.LeafNode.ExtractWithNode(),
		Left:     n.Left.Extract(),
		Right:    n.Right.Extract(),
	}
}

// Extract makes a copy of the node containing only hash references without
// checking the dirty flag.
//
// For LeafNode, it makes a deep copy so that the parent internal node always
// ships it since we cannot address the LeafNode uniquely with NodeID (both the
// internal node and LeafNode have the same path and bit depth).
func (n *InternalNode) ExtractUnchecked() Node {
	return &InternalNode{
		Clean:          true,
		Version:        n.Version,
		Hash:           n.Hash,
		Label:          n.Label,
		LabelBitLength: n.LabelBitLength,
		// LeafNode is always contained in internal node.
		LeafNode: n.LeafNode.ExtractWithNodeUnchecked(),
		Left:     n.Left.ExtractUnchecked(),
		Right:    n.Right.ExtractUnchecked(),
	}
}

// CompactMarshalBinary encodes an internal node into binary form without
// any hash pointers (e.g., for proofs).
func (n *InternalNode) CompactMarshalBinary() (data []byte, err error) {
	// Internal node's LeafNode is always marshaled along the internal node.
	var leafNodeBinary []byte
	if n.LeafNode == nil {
		leafNodeBinary = make([]byte, 1)
		leafNodeBinary[0] = PrefixNilNode
	} else {
		if leafNodeBinary, err = n.LeafNode.Node.MarshalBinary(); err != nil {
			return nil, fmt.Errorf("mkvs: failed to marshal leaf node: %w", err)
		}
	}

	data = make([]byte, 1+VersionSize+DepthSize+len(n.Label)+len(leafNodeBinary))
	pos := 0
	data[pos] = PrefixInternalNode
	pos++
	binary.LittleEndian.PutUint64(data[pos:pos+VersionSize], n.Version)
	pos += VersionSize
	copy(data[pos:pos+DepthSize], n.LabelBitLength.MarshalBinary()[:])
	pos += DepthSize
	copy(data[pos:pos+len(n.Label)], n.Label)
	pos += len(n.Label)
	copy(data[pos:pos+len(leafNodeBinary)], leafNodeBinary[:])
	return
}

// MarshalBinary encodes an internal node into binary form.
func (n *InternalNode) MarshalBinary() (data []byte, err error) {
	data, err = n.CompactMarshalBinary()
	if err != nil {
		return
	}

	leftHash := n.Left.GetHash()
	rightHash := n.Right.GetHash()

	data = append(data, leftHash[:]...)
	data = append(data, rightHash[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled internal node.
func (n *InternalNode) UnmarshalBinary(data []byte) error {
	_, err := n.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled internal node.
func (n *InternalNode) SizedUnmarshalBinary(data []byte) (int, error) {
	if len(data) < 1+VersionSize+DepthSize+1 {
		return 0, ErrMalformedNode
	}

	pos := 0
	if data[pos] != PrefixInternalNode {
		return 0, ErrMalformedNode
	}
	pos++

	n.Version = binary.LittleEndian.Uint64(data[pos : pos+VersionSize])
	pos += VersionSize

	if _, err := n.LabelBitLength.UnmarshalBinary(data[pos:]); err != nil {
		return 0, fmt.Errorf("mkvs: failed to unmarshal LabelBitLength: %w", err)
	}
	labelLen := n.LabelBitLength.ToBytes()
	pos += DepthSize
	if pos+labelLen > len(data) {
		return 0, ErrMalformedNode
	}

	n.Label = make(Key, labelLen)
	copy(n.Label, data[pos:pos+labelLen])
	pos += labelLen
	if pos >= len(data) {
		return 0, ErrMalformedNode
	}

	if data[pos] == PrefixNilNode {
		n.LeafNode = nil
		pos++
	} else {
		leafNode := LeafNode{}
		var leafNodeBinarySize int
		var err error
		if leafNodeBinarySize, err = leafNode.SizedUnmarshalBinary(data[pos:]); err != nil {
			return 0, fmt.Errorf("mkvs: failed to unmarshal leaf node: %w", err)
		}
		n.LeafNode = &Pointer{Clean: true, Hash: leafNode.Hash, Node: &leafNode}
		pos += leafNodeBinarySize
	}

	// Hashes are only present in non-compact serialization.
	if len(data) >= pos+hash.Size*2 {
		var leftHash hash.Hash
		if err := leftHash.UnmarshalBinary(data[pos : pos+hash.Size]); err != nil {
			return 0, fmt.Errorf("mkvs: failed to unmarshal left hash: %w", err)
		}
		pos += hash.Size
		var rightHash hash.Hash
		if err := rightHash.UnmarshalBinary(data[pos : pos+hash.Size]); err != nil {
			return 0, fmt.Errorf("mkvs: failed to unmarshal right hash: %w", err)
		}
		pos += hash.Size

		if leftHash.IsEmpty() {
			n.Left = nil
		} else {
			n.Left = &Pointer{Clean: true, Hash: leftHash}
		}

		if rightHash.IsEmpty() {
			n.Right = nil
		} else {
			n.Right = &Pointer{Clean: true, Hash: rightHash}
		}

		n.UpdateHash()
	}

	n.Clean = true

	return pos, nil
}

// Equal compares a node with some other node.
func (n *InternalNode) Equal(other Node) bool {
	if n == nil && other == nil {
		return true
	}
	if n == nil || other == nil {
		return false
	}
	if other, ok := other.(*InternalNode); ok {
		if n.Clean && other.Clean {
			return n.Hash.Equal(&other.Hash)
		}
		return n.Version == other.Version &&
			n.LeafNode.Equal(other.LeafNode) &&
			n.Left.Equal(other.Left) &&
			n.Right.Equal(other.Right) &&
			n.LabelBitLength == other.LabelBitLength &&
			bytes.Equal(n.Label, other.Label)
	}
	return false
}

// LeafNode is a leaf node containing a key/value pair.
type LeafNode struct {
	Clean bool
	// Version is the version in which the node has been created.
	Version uint64
	Hash    hash.Hash
	Key     Key
	Value   []byte
}

// IsClean returns true if the node is non-dirty.
func (n *LeafNode) IsClean() bool {
	return n.Clean
}

// Size returns the size of this leaf node in bytes.
func (n *LeafNode) Size() uint64 {
	size := LeafNodeSize
	size += uint64(len(n.Key))
	size += uint64(len(n.Value))
	return size
}

// GetHash returns the node's cached hash.
func (n *LeafNode) GetHash() hash.Hash {
	return n.Hash
}

// GetCreatedVersion returns the version in which the node has been created.
func (n *LeafNode) GetCreatedVersion() uint64 {
	return n.Version
}

// UpdateHash updates the node's cached hash by recomputing it.
//
// Does not mark the node as clean.
func (n *LeafNode) UpdateHash() {
	var version [VersionSize]byte
	binary.LittleEndian.PutUint64(version[:], n.Version)

	n.Hash.FromBytes([]byte{PrefixLeafNode}, version[:], n.Key[:], n.Value[:])
}

// Extract makes a copy of the node containing only hash references.
func (n *LeafNode) Extract() Node {
	if !n.Clean {
		panic("mkvs: extract called on dirty node")
	}
	return n.ExtractUnchecked()
}

// Extract makes a copy of the node containing only hash references
// without checking the dirty flag.
func (n *LeafNode) ExtractUnchecked() Node {
	return &LeafNode{
		Clean:   true,
		Version: n.Version,
		Hash:    n.Hash,
		Key:     n.Key,
		Value:   n.Value,
	}
}

// CompactMarshalBinary encodes a leaf node into binary form.
func (n *LeafNode) CompactMarshalBinary() (data []byte, err error) {
	keyData, err := n.Key.MarshalBinary()
	if err != nil {
		return nil, err
	}

	data = make([]byte, 1+VersionSize+len(keyData)+ValueLengthSize+len(n.Value))
	pos := 0
	data[pos] = PrefixLeafNode
	pos++
	binary.LittleEndian.PutUint64(data[pos:pos+VersionSize], n.Version)
	pos += VersionSize
	copy(data[pos:pos+len(keyData)], keyData)
	pos += len(keyData)
	binary.LittleEndian.PutUint32(data[pos:pos+ValueLengthSize], uint32(len(n.Value)))
	pos += ValueLengthSize
	copy(data[pos:], n.Value)
	return
}

// MarshalBinary encodes a leaf node into binary form.
func (n *LeafNode) MarshalBinary() ([]byte, error) {
	return n.CompactMarshalBinary()
}

// UnmarshalBinary decodes a binary marshaled leaf node.
func (n *LeafNode) UnmarshalBinary(data []byte) error {
	_, err := n.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled leaf node.
func (n *LeafNode) SizedUnmarshalBinary(data []byte) (int, error) {
	if len(data) < 1+VersionSize+DepthSize+ValueLengthSize || data[0] != PrefixLeafNode {
		return 0, ErrMalformedNode
	}

	pos := 1
	n.Version = binary.LittleEndian.Uint64(data[pos : pos+VersionSize])
	pos += VersionSize

	var key Key
	keySize, err := key.SizedUnmarshalBinary(data[pos:])
	if err != nil {
		return 0, err
	}
	pos += keySize
	if pos+ValueLengthSize > len(data) {
		return 0, ErrMalformedNode
	}

	valueSize := int(binary.LittleEndian.Uint32(data[pos : pos+ValueLengthSize]))
	pos += ValueLengthSize
	if pos+valueSize > len(data) {
		return 0, ErrMalformedNode
	}

	value := make([]byte, valueSize)
	copy(value, data[pos:pos+valueSize])
	pos += valueSize

	n.Clean = true
	n.Key = key
	n.Value = value

	n.UpdateHash()

	return pos, nil
}

// Equal compares a node with some other node.
func (n *LeafNode) Equal(other Node) bool {
	if n == nil && other == nil {
		return true
	}
	if n == nil || other == nil {
		return false
	}
	if other, ok := other.(*LeafNode); ok {
		if n.Clean && other.Clean {
			return n.Hash.Equal(&other.Hash)
		}
		return n.Version == other.Version &&
			n.Key.Equal(other.Key) &&
			bytes.Equal(n.Value, other.Value)
	}
	return false
}

// UnmarshalBinary unmarshals a node of arbitrary type.
func UnmarshalBinary(bytes []byte) (Node, error) {
	// Nodes can be either Internal or Leaf nodes.
	// Check the first byte and deserialize appropriately.
	var node Node
	if len(bytes) > 1 {
		switch bytes[0] {
		case PrefixLeafNode:
			var leaf LeafNode
			if err := leaf.UnmarshalBinary(bytes); err != nil {
				return nil, err
			}
			node = Node(&leaf)
		case PrefixInternalNode:
			var inode InternalNode
			if err := inode.UnmarshalBinary(bytes); err != nil {
				return nil, err
			}
			node = Node(&inode)
		default:
			return nil, ErrMalformedNode
		}
	} else {
		return nil, ErrMalformedNode
	}
	return node, nil
}
