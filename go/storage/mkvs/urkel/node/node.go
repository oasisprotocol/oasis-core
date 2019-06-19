// Package node defines Urkel tree nodes.
package node

import (
	"bytes"
	"container/list"
	"crypto/sha512"
	"encoding"
	"encoding/binary"
	"fmt"
	"math/bits"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
)

var (
	ErrMalformedNode = errors.New("urkel: malformed node")
	ErrMalformedKey  = errors.New("urkel: malformed key")
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
//
// BitDepth is a sum of bits on the path from the root to the node in compressed
// urkel tree. Depth is a number of hops from the root to the node and is
// provided for convenience e.g. when fetching a subtree of given depth.
//
// If there exist InternalNode and LeafNode having the same Key and BitDepth,
// ID represents the InternalNode.
type ID struct {
	Path     Key
	BitDepth Depth
}

// AtBitDepth returns a ID representing the same path at a specified
// bit depth.
func (n ID) AtBitDepth(bd Depth) ID {
	return ID{Path: n.Path, BitDepth: bd}
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

// Copy makes deep copy of the Pointer to LeafNode excluding LRU and DBInternal.
func (p *Pointer) CopyLeafNodePtr(requireClean bool) *Pointer {
	if p == nil {
		return nil
	}
	if requireClean && !p.Clean {
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

// InternalNode is an internal node with two children and possibly a leaf.
type InternalNode struct {
	Hash           hash.Hash
	Label          Key   // label on the incoming edge
	LabelBitLength Depth // length of the label in bits
	Clean          bool
	LeafNode       *Pointer // for the key ending at this depth
	Left           *Pointer
	Right          *Pointer
}

// UpdateHash updates the node's cached hash by recomputing it.
//
// Does not mark the node as clean.
func (n *InternalNode) UpdateHash() {
	leafNodeHash := n.LeafNode.GetHash()
	leftHash := n.Left.GetHash()
	rightHash := n.Right.GetHash()
	labelHash := sha512.Sum512_256(append(n.LabelBitLength.MarshalBinary(), n.Label...))

	n.Hash.FromBytes([]byte{PrefixInternalNode}, labelHash[:], leafNodeHash[:], leftHash[:], rightHash[:])
}

// GetHash returns the node's cached hash.
func (n *InternalNode) GetHash() hash.Hash {
	return n.Hash
}

// Extract makes a copy of the node containing only hash references.
//
// For LeafNode, it makes a deep copy so that the parent internal node always
// ships it since we cannot address the LeafNode uniquely with NodeID (both the
// internal node and LeafNode have the same path and bit depth).
func (n *InternalNode) Extract() Node {
	if !n.Clean {
		panic("urkel: extract called on dirty node")
	}
	return &InternalNode{
		Clean:          true,
		Hash:           n.Hash,
		Label:          n.Label,
		LabelBitLength: n.LabelBitLength,
		// LeafNode is always contained in internal node.
		LeafNode: n.LeafNode.CopyLeafNodePtr(true),
		Left:     n.Left.ExtractUnchecked(),
		Right:    n.Right.ExtractUnchecked(),
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
		Hash:           n.Hash,
		Label:          n.Label,
		LabelBitLength: n.LabelBitLength,
		// LeafNode is always contained in internal node.
		LeafNode: n.LeafNode.CopyLeafNodePtr(false),
		Left:     n.Left.ExtractUnchecked(),
		Right:    n.Right.ExtractUnchecked(),
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
	// Internal node's LeafNode is always marshaled along the internal node.
	var leafNodeBinary []byte
	if n.LeafNode == nil {
		leafNodeBinary = make([]byte, 1)
		leafNodeBinary[0] = PrefixNilNode
	} else {
		if leafNodeBinary, err = n.LeafNode.Node.MarshalBinary(); err != nil {
			return []byte{}, errors.Wrap(err, "urkel: failed to marshal leaf node")
		}
	}

	leftHash := n.Left.GetHash()
	rightHash := n.Right.GetHash()

	data = make([]byte, 1+int(unsafe.Sizeof(n.LabelBitLength))+len(n.Label)+len(leafNodeBinary)+hash.Size*2)
	pos := 0
	data[pos] = PrefixInternalNode
	pos++
	copy(data[pos:pos+int(unsafe.Sizeof(n.LabelBitLength))], n.LabelBitLength.MarshalBinary()[:])
	pos += int(unsafe.Sizeof(n.LabelBitLength))
	copy(data[pos:pos+len(n.Label)], n.Label)
	pos += len(n.Label)
	copy(data[pos:pos+len(leafNodeBinary)], leafNodeBinary[:])
	pos += len(leafNodeBinary)
	copy(data[pos:pos+hash.Size], leftHash[:])
	pos += hash.Size
	copy(data[pos:], rightHash[:])
	return
}

// UnmarshalBinary decodes a binary marshaled internal node.
func (n *InternalNode) UnmarshalBinary(data []byte) error {
	_, err := n.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled internal node.
func (n *InternalNode) SizedUnmarshalBinary(data []byte) (int, error) {
	if len(data) < 1+int(unsafe.Sizeof(n.LabelBitLength))+1+hash.Size*2 {
		return 0, ErrMalformedNode
	}

	pos := 0
	if data[pos] != PrefixInternalNode {
		return 0, ErrMalformedNode
	}
	pos++

	if _, err := n.LabelBitLength.UnmarshalBinary(data[pos:]); err != nil {
		return 0, errors.Wrap(err, "urkel: failed to unmarshal LabelBitLength")
	}
	labelLen := n.LabelBitLength.ToBytes()
	pos += int(unsafe.Sizeof(n.LabelBitLength))

	n.Label = make(Key, labelLen)
	copy(n.Label, data[pos:pos+labelLen])
	pos += labelLen

	if data[pos] == PrefixNilNode {
		n.LeafNode = nil
		pos++
	} else {
		leafNode := LeafNode{}
		var leafNodeBinarySize int
		var err error
		if leafNodeBinarySize, err = leafNode.SizedUnmarshalBinary(data[pos:]); err != nil {
			return 0, errors.Wrap(err, "urkel: failed to unmarshal leaf node")
		}
		n.LeafNode = &Pointer{Clean: true, Hash: leafNode.Hash, Node: &leafNode}
		pos += leafNodeBinarySize
	}

	var leftHash hash.Hash
	if err := leftHash.UnmarshalBinary(data[pos : pos+hash.Size]); err != nil {
		return 0, errors.Wrap(err, "urkel: failed to unmarshal left hash")
	}
	pos += hash.Size
	var rightHash hash.Hash
	if err := rightHash.UnmarshalBinary(data[pos : pos+hash.Size]); err != nil {
		return 0, errors.Wrapf(err, "urkel: failed to unmarshal right hash")
	}
	pos += hash.Size

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
			return n.Hash.Equal(&other.Hash) && n.LabelBitLength == other.LabelBitLength && bytes.Equal(n.Label, other.Label)
		}
		return n.LeafNode.Equal(other.LeafNode) && n.Left.Equal(other.Left) && n.Right.Equal(other.Right) && n.LabelBitLength == other.LabelBitLength && bytes.Equal(n.Label, other.Label)
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
	if len(data) < 1+DepthSize || data[0] != PrefixLeafNode {
		return 0, ErrMalformedNode
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

// Depth determines the maximum length of the key in bits.
//
// maxKeyLengthInBits = 2^size_of(Depth)*8
type Depth uint16

// DepthSize is the size of Depth in bytes.
const DepthSize = int(unsafe.Sizeof(Depth(0)))

// ToBytes returns the number of bytes needed to fit given bits.
func (dt Depth) ToBytes() int {
	size := dt / 8
	if dt%8 != 0 {
		size++
	}
	return int(size)
}

// MarshalBinary encodes a Depth into binary form.
func (dt Depth) MarshalBinary() []byte {
	data := make([]byte, DepthSize)
	binary.LittleEndian.PutUint16(data, uint16(dt))
	return data
}

// MarshalBinary encodes a Depth into binary form.
func (dt *Depth) UnmarshalBinary(data []byte) (int, error) {
	*dt = Depth(binary.LittleEndian.Uint16(data[0:DepthSize]))
	return DepthSize, nil
}

// MarshalBinary encodes a key length in bytes + key into binary form.
func (k Key) MarshalBinary() (data []byte, err error) {
	data = make([]byte, DepthSize+len(k))
	binary.LittleEndian.PutUint16(data[0:DepthSize], uint16(len(k)))
	if k != nil {
		copy(data[DepthSize:], k[:])
	}
	return
}

// UnmarshalBinary decodes a binary marshaled key including the length in bytes.
func (k *Key) UnmarshalBinary(data []byte) error {
	_, err := k.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled key incl. length in bytes.
func (k *Key) SizedUnmarshalBinary(data []byte) (int, error) {
	if len(data) < DepthSize {
		return 0, ErrMalformedKey
	}

	keyLen := binary.LittleEndian.Uint16(data[0:DepthSize])
	if len(data) < DepthSize+int(keyLen) {
		return 1, ErrMalformedKey
	}

	if keyLen > 0 {
		*k = make([]byte, keyLen)
		copy(*k, data[DepthSize:DepthSize+int(keyLen)])
	}
	return DepthSize + int(keyLen), nil
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
func (k Key) BitLength() Depth {
	return Depth(len(k[:]) * 8)
}

// GetKeyBit returns the given bit of the key.
func (k Key) GetBit(bit Depth) bool {
	return k[bit/8]&(1<<(7-(bit%8))) != 0
}

// SetKeyBit sets the bit at the given position bit to value val.
//
// This function is immutable and returns a new instance of Key
func (k Key) SetBit(bit Depth, val bool) Key {
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

// Split performs bit-wise split of the key.
//
// keyLen is the length of the key in bits and splitPoint is the index of the
// first suffix bit.
// This function is immutable and returns two new instances of Key.
func (k Key) Split(splitPoint Depth, keyLen Depth) (prefix Key, suffix Key) {
	if splitPoint > keyLen {
		panic(fmt.Sprintf("urkel: splitPoint %+v greater than keyLen %+v", splitPoint, keyLen))
	}
	prefixLen := Depth(splitPoint.ToBytes())
	suffixLen := Depth((keyLen - splitPoint).ToBytes())
	prefix = make(Key, prefixLen)
	suffix = make(Key, suffixLen)

	copy(prefix[:], k[:])
	// Clean the remainder of the byte.
	if splitPoint%8 != 0 {
		prefix[prefixLen-1] &= 0xff << (8 - splitPoint%8)
	}

	for i := Depth(0); i < suffixLen; i++ {
		// First set the left chunk of the byte
		suffix[i] = k[i+splitPoint/8] << (splitPoint % 8)
		// ...and the right chunk, if we haven't reached the end of k yet.
		if splitPoint%8 != 0 && i+splitPoint/8+1 != Depth(len(k)) {
			suffix[i] |= k[i+splitPoint/8+1] >> (8 - splitPoint%8)
		}
	}

	return
}

// Merge bit-wise merges key of given length with another key of given length.
//
// keyLen is the length of the original key in bits and k2Len is the length of
// another key in bits.
// This function is immutable and returns a new instance of Key.
func (k Key) Merge(keyLen Depth, k2 Key, k2Len Depth) Key {
	newKey := make(Key, (keyLen + k2Len).ToBytes())
	copy(newKey[:], k[:])

	for i := 0; i < len(k2); i++ {
		// First set the right chunk of the previous byte
		if keyLen%8 != 0 && len(k) > 0 {
			newKey[len(k)+i-1] |= k2[i] >> (keyLen % 8)
		}
		// ...and the next left chunk, if we haven't reached the end of newKey
		// yet.
		if len(k)+i < len(newKey) {
			// another mod 8 to prevent bit shifting for 8 bits
			newKey[len(k)+i] |= k2[i] << ((8 - keyLen%8) % 8)
		}
	}

	return newKey
}

// AppendBit appends the given bit to the key.
//
// This function is immutable and returns a new instance of Key.
func (k Key) AppendBit(keyLen Depth, val bool) Key {
	newKey := make(Key, (keyLen + 1).ToBytes())
	copy(newKey[:len(k)], k[:])

	if val {
		newKey[keyLen/8] |= 0x80 >> (keyLen % 8)
	} else {
		newKey[keyLen/8] &^= 0x80 >> (keyLen % 8)
	}

	return newKey
}

// CommonPrefix computes length of common prefix of k and k2.
//
// Additionally, keyBitLen and k2bitLen are key lengths in bits of k and k2
// respectively.
func (k Key) CommonPrefixLen(keyBitLen Depth, k2 Key, k2bitLen Depth) (bitLength Depth) {
	minKeyLen := len(k)
	if len(k2) < len(k) {
		minKeyLen = len(k2)
	}

	// Compute the common prefix byte-wise.
	i := Depth(0)
	for ; i < Depth(minKeyLen) && k[i] == k2[i]; i++ {
	}

	// Prefixes match i bytes and maybe some more bits below.
	bitLength = i * 8

	if i != Depth(len(k)) && i != Depth(len(k2)) {
		// We got a mismatch somewhere along the way. We need to compute how
		// many additional bits in i-th byte match.
		bitLength += Depth(bits.LeadingZeros8(k[i] ^ k2[i]))
	}

	// In any case, bitLength should never exceed length of the shorter key.
	if bitLength > keyBitLen {
		bitLength = keyBitLen
	}
	if bitLength > k2bitLen {
		bitLength = k2bitLen
	}

	return
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
		return 0, ErrMalformedNode
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
