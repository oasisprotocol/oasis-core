// Package internal defines Urkel tree internals.
package internal

import (
	"bytes"
	"container/list"
	"encoding"
	"errors"
	"fmt"

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
)

var (
	_ encoding.BinaryMarshaler   = (*InternalNode)(nil)
	_ encoding.BinaryUnmarshaler = (*InternalNode)(nil)
	_ encoding.BinaryMarshaler   = (*LeafNode)(nil)
	_ encoding.BinaryUnmarshaler = (*LeafNode)(nil)
)

// NodeID is a root-relative node identifier which uniquely identifies
// a node under a given root.
type NodeID struct {
	Path  hash.Hash
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
}

// InternalNode is an internal node with two children.
type InternalNode struct { // nolint: golint
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

	return &InternalNode{
		Clean: true,
		Hash:  n.Hash,
		Left:  n.Left.Extract(),
		Right: n.Right.Extract(),
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
	if len(data) != 1+hash.Size*2 {
		return ErrMalformed
	}
	if data[0] != PrefixInternalNode {
		return ErrMalformed
	}

	var leftHash hash.Hash
	if err := leftHash.UnmarshalBinary(data[1 : 1+hash.Size]); err != nil {
		return err
	}
	var rightHash hash.Hash
	if err := rightHash.UnmarshalBinary(data[1+hash.Size:]); err != nil {
		return err
	}

	n.Clean = false
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

	return nil
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
	data = make([]byte, 1+hash.Size*2)
	data[0] = PrefixLeafNode
	copy(data[1:1+hash.Size], n.Key[:])
	copy(data[1+hash.Size:], n.Value.Hash[:])
	return
}

// UnmarshalBinary decodes a binary marshaled leaf node.
func (n *LeafNode) UnmarshalBinary(data []byte) error {
	if len(data) != 1+hash.Size*2 {
		return ErrMalformed
	}
	if data[0] != PrefixLeafNode {
		return ErrMalformed
	}

	var key hash.Hash
	if err := key.UnmarshalBinary(data[1 : 1+hash.Size]); err != nil {
		return err
	}
	var valueHash hash.Hash
	if err := valueHash.UnmarshalBinary(data[1+hash.Size:]); err != nil {
		return err
	}

	n.Clean = false
	n.Key = key
	n.Value = &Value{Clean: true, Hash: valueHash}

	return nil
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
