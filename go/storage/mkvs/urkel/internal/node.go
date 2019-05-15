// Package internal defines Urkel tree internals.
package internal

import (
	"bytes"
	"container/list"
	"encoding"
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
)

var (
	ErrMalformed    = errors.New("urkel: malformed node")
	ErrMalformedKey = errors.New("urkel: malformed key")
)

const (
	// Prefix used in hash computations of leaf nodes.
	PrefixLeafNode byte = 0x00
	// Prefix used in hash computations of internal nodes.
	PrefixInternalNode byte = 0x01
	// Prefix used to mark a nil pointer in a subtree serialization.
	PrefixNilNode byte = 0x02
)

var (
	_ encoding.BinaryMarshaler   = (*InternalNode)(nil)
	_ encoding.BinaryUnmarshaler = (*InternalNode)(nil)
	_ encoding.BinaryMarshaler   = (*LeafNode)(nil)
	_ encoding.BinaryUnmarshaler = (*LeafNode)(nil)
	_ encoding.BinaryMarshaler   = (*Value)(nil)
	_ encoding.BinaryUnmarshaler = (*Value)(nil)
)

// NodeID is a root-relative node identifier which uniquely identifies
// a node under a given root.
type NodeID struct {
	Path  Key
	Depth uint8
}

// AtDepth returns a NodeID representing the same path at a specified
// depth.
func (n NodeID) AtDepth(d uint8) NodeID {
	return NodeID{Path: n.Path, Depth: d}
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
	if p == nil {
		return nil
	}
	if !p.Clean {
		panic("urkel: extract called on dirty pointer")
	}

	return &Pointer{
		Clean: true,
		Hash:  p.Hash,
	}
}

// Copy makes deep copy of the Pointer to LeafNode excluding LRU and DBInternal.
func (p *Pointer) CopyLeafNodePtr() *Pointer {
	if p == nil {
		return nil
	}
	if !p.Clean {
		panic("urkel: CopyLeafNodePtr called on dirty pointer")
	}

	switch n := p.Node.(type) {
	case *LeafNode:
		var node = n.Copy()
		return &Pointer{
			Clean: true,
			Hash:  p.Hash,
			Node:  &node,
		}

	}

	panic("urkel: CopyLeafNodePtr called on a non-leaf pointer")
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

	// Validate that the node is internally consistent with the given
	// node hash. This does NOT verify that the whole subtree is
	// consistent.
	//
	// Calling this on a dirty node will return an error.
	Validate(h hash.Hash) error

	// Equal compares a node with another node.
	Equal(other Node) bool
}

// InternalNode is an internal node with two children and possibly a leaf.
type InternalNode struct { // nolint: golint
	Clean    bool
	Hash     hash.Hash
	LeafNode *Pointer // for the key ending at this depth
	Left     *Pointer
	Right    *Pointer
}

// UpdateHash updates the node's cached hash by recomputing it.
//
// Does not mark the node as clean.
func (n *InternalNode) UpdateHash() {
	leafNodeHash := n.LeafNode.GetHash()
	leftHash := n.Left.GetHash()
	rightHash := n.Right.GetHash()

	n.Hash.FromBytes([]byte{PrefixInternalNode}, leafNodeHash[:], leftHash[:], rightHash[:])
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

	// Extract Left and Right pointers. For LeafNode, make a deep copy so that
	// the parent internal node always ships it since we cannot address the
	// LeafNode uniquely with NodeID (both the internal node and LeafNode have
	// the same path and depth).
	return &InternalNode{
		Clean:    true,
		Hash:     n.Hash,
		LeafNode: n.LeafNode.CopyLeafNodePtr(),
		Left:     n.Left.Extract(),
		Right:    n.Right.Extract(),
	}
}

// Validate that the node is internally consistent with the given
// node hash. This does NOT verify that the whole subtree is
// consistent.
//
// Calling this on a dirty node will return an error.
func (n *InternalNode) Validate(h hash.Hash) error {
	if !n.LeafNode.IsClean() || !n.Left.IsClean() || !n.Right.IsClean() {
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
	leafNodeHash := n.LeafNode.GetHash()
	leftHash := n.Left.GetHash()
	rightHash := n.Right.GetHash()

	data = make([]byte, 1+hash.Size*3)
	data[0] = PrefixInternalNode
	copy(data[1:1+hash.Size], leafNodeHash[:])
	copy(data[1+hash.Size:1+2*hash.Size], leftHash[:])
	copy(data[1+2*hash.Size:], rightHash[:])
	return
}

// UnmarshalBinary decodes a binary marshaled internal node.
func (n *InternalNode) UnmarshalBinary(data []byte) error {
	_, err := n.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled internal node.
func (n *InternalNode) SizedUnmarshalBinary(data []byte) (int, error) {
	if len(data) < 1+hash.Size*3 {
		return 0, ErrMalformed
	}
	if data[0] != PrefixInternalNode {
		return 0, ErrMalformed
	}

	var leafNodeHash hash.Hash
	if err := leafNodeHash.UnmarshalBinary(data[1 : 1+hash.Size]); err != nil {
		return 0, errors.Wrap(err, "urkel: failed to unmarshal lealf node hash")
	}
	var leftHash hash.Hash
	if err := leftHash.UnmarshalBinary(data[1+hash.Size : 1+hash.Size*2]); err != nil {
		return 0, errors.Wrap(err, "urkel: failed to unmarshal left hash")
	}
	var rightHash hash.Hash
	if err := rightHash.UnmarshalBinary(data[1+hash.Size*2 : 1+hash.Size*3]); err != nil {
		return 0, errors.Wrapf(err, "urkel: failed to unmarshal right hash")
	}

	n.Clean = true
	if leafNodeHash.IsEmpty() {
		n.LeafNode = nil
	} else {
		n.LeafNode = &Pointer{Clean: true, Hash: leafNodeHash}
	}

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

	return 1 + hash.Size*3, nil
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
		return n.LeafNode.Equal(other.LeafNode) && n.Left.Equal(other.Left) && n.Right.Equal(other.Right)
	}
	return false
}

// LeafNode is a leaf node containing a key/value pair.
type LeafNode struct {
	Clean bool
	Hash  hash.Hash
	Key   Key
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

	return &LeafNode{
		Clean: true,
		Hash:  n.Hash,
		Key:   n.Key,
		Value: n.Value.Extract(),
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
	keyData, err := n.Key.MarshalBinary()
	if err != nil {
		return nil, err
	}

	valueData, err := n.Value.MarshalBinary()
	if err != nil {
		return nil, err
	}
	data = make([]byte, 1+len(keyData)+len(valueData))
	data[0] = PrefixLeafNode
	copy(data[1:1+len(keyData)], keyData)
	copy(data[1+len(keyData):], valueData)
	return
}

// UnmarshalBinary decodes a binary marshaled leaf node.
func (n *LeafNode) UnmarshalBinary(data []byte) error {
	_, err := n.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled leaf node.
func (n *LeafNode) SizedUnmarshalBinary(data []byte) (int, error) {
	if len(data) < 2 {
		return 0, ErrMalformed
	}
	if data[0] != PrefixLeafNode {
		return 0, ErrMalformed
	}

	key := Key{}
	keySize, err := key.SizedUnmarshalBinary(data[1:])
	if err != nil {
		return 0, err
	}

	value := &Value{}
	valueSize, err := value.SizedUnmarshalBinary(data[1+keySize:])
	if err != nil {
		return 0, err
	}

	n.Clean = true
	n.Key = key
	n.Value = value

	n.UpdateHash()

	return 1 + keySize + valueSize, nil
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
		return n.Key.Equal(other.Key) && n.Value.EqualPointer(other.Value)
	}
	return false
}

// Make a deep copy of the leaf node.
func (n *LeafNode) Copy() LeafNode {
	var val = n.Value.Copy()
	var node = LeafNode{
		Clean: n.Clean,
		Hash:  n.Hash,
		Key:   make(Key, len(n.Key)),
		Value: &val,
	}

	copy(node.Key, n.Key)

	return node
}

// Key holds variable-length key.
type Key []byte

// MarshalBinary encodes a key into binary form.
func (k Key) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1+len(k))
	data[0] = uint8(len(k))
	if k != nil {
		copy(data[1:], k[:])
	}
	return
}

// UnmarshalBinary decodes a binary marshaled key.
func (k *Key) UnmarshalBinary(data []byte) error {
	_, err := k.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled key.
func (k *Key) SizedUnmarshalBinary(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, ErrMalformedKey
	}

	keyLen := data[0]
	if len(data) < int(1+keyLen) {
		return 1, ErrMalformedKey
	}

	if keyLen > 0 {
		*k = make([]byte, keyLen)
		copy(*k, data[1:1+keyLen])
	}
	return int(1 + keyLen), nil
}

// Equal compares the key with some other key.
func (k Key) Equal(other Key) bool {
	if k != nil {
		return bytes.Equal(k, other)
	}
	return other == nil
}

// ToMapKey returns the key in a form to be used as a Go's map key.
func ToMapKey(k []byte) string {
	return string(k)
}

// BitLength returns the length of the key in bits.
func (k Key) BitLength() int {
	return len(k[:]) * 8
}

// GetKeyBit returns the given bit of the key.
func (k Key) GetBit(bit uint8) bool {
	return k[bit/8]&(1<<(7-(bit%8))) != 0
}

// SetKeyBit sets the bit at the given position bit to value val.
//
// This function is immutable and returns a new instance of internal.Key
func (k Key) SetBit(bit uint8, val bool) Key {
	var kb = make(Key, len(k))
	copy(kb[:], k[:])
	mask := byte(1 << (7 - (bit % 8)))
	if val {
		kb[bit/8] |= mask
	} else {
		kb[bit/8] &= mask
	}
	return kb
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

// Creates a deep copy of the Value without LRU.
func (v *Value) Copy() Value {
	var value = Value{
		Clean: v.Clean,
		Hash:  v.Hash,
		Value: make([]byte, len(v.Value)),
	}

	copy(value.Value, v.Value)

	return value
}
