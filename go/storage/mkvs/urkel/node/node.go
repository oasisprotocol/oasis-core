// Package node defines Urkel tree nodes.
package node

import (
	"bytes"
	"container/list"
	"encoding"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
)

var (
	ErrMalformed = errors.New("urkel: malformed node")
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
	// InternalNodeSize is the size of an internal node in memory.
	InternalNodeSize = uint64(unsafe.Sizeof(InternalNode{})) + 2*PointerSize
	// ValueSize is the size of an empty value node in memory.
	ValueSize = uint64(unsafe.Sizeof(Value{}))
	// LeafNodeSize is the size of a leaf node in memory.
	LeafNodeSize = uint64(unsafe.Sizeof(LeafNode{})) + ValueSize
)

var (
	_ encoding.BinaryMarshaler   = (*InternalNode)(nil)
	_ encoding.BinaryUnmarshaler = (*InternalNode)(nil)
	_ encoding.BinaryMarshaler   = (*LeafNode)(nil)
	_ encoding.BinaryUnmarshaler = (*LeafNode)(nil)
	_ encoding.BinaryMarshaler   = (*Value)(nil)
	_ encoding.BinaryUnmarshaler = (*Value)(nil)
	_ cbor.Marshaler             = (*Root)(nil)
	_ cbor.Unmarshaler           = (*Root)(nil)
)

// Root is a storage root.
type Root struct {
	// Namespace is the chain namespace under which the root is stored.
	Namespace common.Namespace `codec:"ns"`
	// Round is the chain round in which the root is stored.
	Round uint64 `codec:"round"`
	// Hash is the merkle root hash.
	Hash hash.Hash `codec:"hash"`
}

// String returns the string representation of a storage root.
func (r Root) String() string {
	return fmt.Sprintf("<Root ns=%s round=%d hash=%s>", r.Namespace, r.Round, r.Hash)
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (r *Root) MarshalCBOR() []byte {
	return cbor.Marshal(r)
}

// UnmarshalCBOR decodes a CBOR marshaled root.
func (r *Root) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, r)
}

// Empty sets the storage root to an empty root.
func (r *Root) Empty() {
	var emptyNs common.Namespace
	r.Namespace = emptyNs
	r.Round = 0
	r.Hash.Empty()
}

// IsEmpty checks whether the storage root is empty.
func (r *Root) IsEmpty() bool {
	var emptyNs common.Namespace
	if !r.Namespace.Equal(&emptyNs) {
		return false
	}

	if r.Round != 0 {
		return false
	}

	return r.Hash.IsEmpty()
}

// Equal compares against another root for equality.
func (r *Root) Equal(other *Root) bool {
	if !r.Namespace.Equal(&other.Namespace) {
		return false
	}

	if r.Round != other.Round {
		return false
	}

	return r.Hash.Equal(&other.Hash)
}

// Follows checks if another root follows the given root. A root follows
// another iff the namespace matches and the round is either equal or
// exactly one higher.
//
// It is the responsibility of the caller to check if the merkle roots
// follow each other.
func (r *Root) Follows(other *Root) bool {
	if !r.Namespace.Equal(&other.Namespace) {
		return false
	}

	if r.Round != other.Round && r.Round != other.Round+1 {
		return false
	}

	return true
}

// EncodedHash returns the encoded cryptographic hash of the storage root.
func (r *Root) EncodedHash() hash.Hash {
	var hh hash.Hash
	hh.From(r)
	return hh
}

// ID is a root-relative node identifier which uniquely identifies
// a node under a given root.
type ID struct {
	Path  hash.Hash
	Depth uint8
}

// AtDepth returns a ID representing the same path at a specified
// depth.
func (n ID) AtDepth(d uint8) ID {
	return ID{Path: n.Path, Depth: d}
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
		panic("urkel: extract called on dirty pointer")
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

// Equal compares two pointers for equality.
func (p *Pointer) Equal(other *Pointer) bool {
	if p.Clean && other.Clean {
		return p.Hash.Equal(&other.Hash)
	}
	return p.Node != nil && other.Node != nil && p.Node.Equal(other.Node)
}

// Node is either an InternalNode or a LeafNode.
type Node interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler

	// GetHash returns the node's cached hash.
	GetHash() hash.Hash

	// UpdateHash updates the node's cached hash by recomputing it.
	//
	// Does not mark the node as clean.
	UpdateHash()

	// Extract makes a copy of the node containing only hash references.
	Extract() Node

	// ExtractUnchecked makes a copy of the node containing only hash
	// references without checking the dirty flag.
	ExtractUnchecked() Node

	// Validate that the node is internally consistent with the given
	// node hash. This does NOT verify that the whole subtree is
	// consistent.
	//
	// Calling this on a dirty node will return an error.
	Validate(h hash.Hash) error

	// Equal compares a node with another node.
	Equal(other Node) bool
}

// InternalNode is an internal node with two children.
type InternalNode struct {
	Clean bool
	Hash  hash.Hash
	Left  *Pointer
	Right *Pointer
}

// UpdateHash updates the node's cached hash by recomputing it.
//
// Does not mark the node as clean.
func (n *InternalNode) UpdateHash() {
	leftHash := n.Left.GetHash()
	rightHash := n.Right.GetHash()

	n.Hash.FromBytes([]byte{PrefixInternalNode}, leftHash[:], rightHash[:])
}

// GetHash returns the node's cached hash.
func (n *InternalNode) GetHash() hash.Hash {
	return n.Hash
}

// Extract makes a copy of the node containing only hash references.
func (n *InternalNode) Extract() Node {
	if !n.Clean {
		panic("urkel: extract called on dirty node")
	}
	return n.ExtractUnchecked()
}

// Extract makes a copy of the node containing only hash references
// without checking the dirty flag.
func (n *InternalNode) ExtractUnchecked() Node {
	return &InternalNode{
		Clean: true,
		Hash:  n.Hash,
		Left:  n.Left.ExtractUnchecked(),
		Right: n.Right.ExtractUnchecked(),
	}
}

// Validate that the node is internally consistent with the given
// node hash. This does NOT verify that the whole subtree is
// consistent.
//
// Calling this on a dirty node will return an error.
func (n *InternalNode) Validate(h hash.Hash) error {
	if !n.Left.IsClean() || !n.Right.IsClean() {
		return errors.New("urkel: node has dirty pointers")
	}

	n.UpdateHash()

	if !h.Equal(&n.Hash) {
		return fmt.Errorf("urkel: node hash mismatch (expected: %s got: %s)",
			h.String(),
			n.Hash.String(),
		)
	}

	return nil
}

// MarshalBinary encodes an internal node into binary form.
func (n *InternalNode) MarshalBinary() (data []byte, err error) {
	leftHash := n.Left.GetHash()
	rightHash := n.Right.GetHash()

	data = make([]byte, 1+hash.Size*2)
	data[0] = PrefixInternalNode
	copy(data[1:1+hash.Size], leftHash[:])
	copy(data[1+hash.Size:], rightHash[:])
	return
}

// UnmarshalBinary decodes a binary marshaled internal node.
func (n *InternalNode) UnmarshalBinary(data []byte) error {
	_, err := n.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled internal node.
func (n *InternalNode) SizedUnmarshalBinary(data []byte) (int, error) {
	if len(data) < 1+hash.Size*2 {
		return 0, ErrMalformed
	}
	if data[0] != PrefixInternalNode {
		return 0, ErrMalformed
	}

	var leftHash hash.Hash
	if err := leftHash.UnmarshalBinary(data[1 : 1+hash.Size]); err != nil {
		return 0, errors.Wrap(err, "urkel: failed to unmarshal left hash")
	}
	var rightHash hash.Hash
	if err := rightHash.UnmarshalBinary(data[1+hash.Size : 1+hash.Size*2]); err != nil {
		return 0, errors.Wrapf(err, "urkel: failed to unmarshal right hash")
	}

	n.Clean = true
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

	return 1 + hash.Size*2, nil
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
		return n.Left.Equal(other.Left) && n.Right.Equal(other.Right)
	}
	return false
}

// LeafNode is a leaf node containing a key/value pair.
type LeafNode struct {
	Clean bool
	Hash  hash.Hash
	Key   hash.Hash
	Value *Value
}

// GetHash returns the node's cached hash.
func (n *LeafNode) GetHash() hash.Hash {
	return n.Hash
}

// UpdateHash updates the node's cached hash by recomputing it.
//
// Does not mark the node as clean.
func (n *LeafNode) UpdateHash() {
	n.Hash.FromBytes([]byte{PrefixLeafNode}, n.Key[:], n.Value.Hash[:])
}

// Extract makes a copy of the node containing only hash references.
func (n *LeafNode) Extract() Node {
	if !n.Clean {
		panic("urkel: extract called on dirty node")
	}
	return n.ExtractUnchecked()
}

// Extract makes a copy of the node containing only hash references
// without checking the dirty flag.
func (n *LeafNode) ExtractUnchecked() Node {
	return &LeafNode{
		Clean: true,
		Hash:  n.Hash,
		Key:   n.Key,
		Value: n.Value.ExtractUnchecked(),
	}
}

// Validate that the node is internally consistent with the given
// node hash. This does NOT verify that the whole subtree is
// consistent.
//
// Calling this on a dirty node will return an error.
func (n *LeafNode) Validate(h hash.Hash) error {
	if !n.Value.Clean {
		return errors.New("urkel: node has dirty value")
	}

	n.UpdateHash()

	if !h.Equal(&n.Hash) {
		return fmt.Errorf("urkel: node hash mismatch (expected: %s got: %s)",
			h.String(),
			n.Hash.String(),
		)
	}

	return nil
}

// MarshalBinary encodes a leaf node into binary form.
func (n *LeafNode) MarshalBinary() (data []byte, err error) {
	valueData, err := n.Value.MarshalBinary()
	if err != nil {
		return nil, err
	}
	data = make([]byte, 1+hash.Size+len(valueData))
	data[0] = PrefixLeafNode
	copy(data[1:1+hash.Size], n.Key[:])
	copy(data[1+hash.Size:], valueData)
	return
}

// UnmarshalBinary decodes a binary marshaled leaf node.
func (n *LeafNode) UnmarshalBinary(data []byte) error {
	_, err := n.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled leaf node.
func (n *LeafNode) SizedUnmarshalBinary(data []byte) (int, error) {
	if len(data) < 1+hash.Size {
		return 0, ErrMalformed
	}
	if data[0] != PrefixLeafNode {
		return 0, ErrMalformed
	}

	var key hash.Hash
	if err := key.UnmarshalBinary(data[1 : 1+hash.Size]); err != nil {
		return 0, errors.Wrap(err, "urkel: failed to unmarshal hash")
	}

	value := &Value{}
	valueSize, err := value.SizedUnmarshalBinary(data[1+hash.Size:])
	if err != nil {
		return 0, err
	}

	n.Clean = true
	n.Key = key
	n.Value = value

	n.UpdateHash()

	return 1 + hash.Size + valueSize, nil
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
		return n.Key.Equal(&other.Key) && n.Value.EqualPointer(other.Value)
	}
	return false
}

// Value holds the value.
type Value struct {
	Clean bool
	Hash  hash.Hash
	Value []byte
	LRU   *list.Element
}

// GetHash returns the value's cached hash.
func (v *Value) GetHash() hash.Hash {
	return v.Hash
}

// UpdateHash updates the value's cached hash by recomputing it.
//
// Does not mark the node as clean.
func (v *Value) UpdateHash() {
	v.Hash.FromBytes(v.Value)
}

// Equal compares the value with some other value.
func (v *Value) Equal(other []byte) bool {
	if v.Value != nil {
		return bytes.Equal(v.Value, other)
	}

	var otherHash hash.Hash
	otherHash.FromBytes(other)
	return v.Hash.Equal(&otherHash)
}

// EqualPointer compares the value pointer with some other value pointer.
func (v *Value) EqualPointer(other *Value) bool {
	if v == nil && other == nil {
		return true
	}
	if v == nil || other == nil {
		return true
	}
	return v.Equal(other.Value)
}

// Extract makes a copy of the value containing only hash references.
func (v *Value) Extract() *Value {
	if !v.Clean {
		panic("urkel: extract called on dirty value")
	}
	return v.ExtractUnchecked()
}

// Extract makes a copy of the value containing only hash references
// without checking the dirty flag.
func (v *Value) ExtractUnchecked() *Value {
	return &Value{
		Clean: true,
		Hash:  v.Hash,
		Value: v.Value,
	}
}

// Validate that the value is internally consistent with the given
// value hash.
func (v *Value) Validate(h hash.Hash) error {
	v.UpdateHash()

	if !h.Equal(&v.Hash) {
		return fmt.Errorf("urkel: value hash mismatch (expected: %s got: %s)",
			h.String(),
			v.Hash.String(),
		)
	}

	return nil
}

// MarshalBinary encodes a value into binary form.
func (v *Value) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4+len(v.Value))
	binary.LittleEndian.PutUint32(data[:4], uint32(len(v.Value)))
	if v.Value != nil {
		copy(data[4:], v.Value)
	}
	return
}

// UnmarshalBinary decodes a binary marshaled value.
func (v *Value) UnmarshalBinary(data []byte) error {
	_, err := v.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled value.
func (v *Value) SizedUnmarshalBinary(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, ErrMalformed
	}

	valueLen := int(binary.LittleEndian.Uint32(data[:4]))
	v.Value = nil
	v.Clean = true
	if valueLen > 0 {
		v.Value = make([]byte, valueLen)
		copy(v.Value, data[4:])
	}
	v.UpdateHash()
	return valueLen + 4, nil
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
			return nil, ErrMalformed
		}
	} else {
		return nil, ErrMalformed
	}
	return node, nil
}
