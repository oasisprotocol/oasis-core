package syncer

import (
	"encoding/binary"
	"errors"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

const (
	// Length of a serialized subtree index.
	treeIndexLen = 2
	// Length of a serialized subtree pointer: index + flag byte
	treePointerLen = treeIndexLen + 1
)

var (
	ErrTooManyFullNodes    = errors.New("urkel: too many full nodes")
	ErrInvalidSubtreeIndex = errors.New("urkel: invalid subtree index")
)

// SubtreeIndex is a subtree index.
type SubtreeIndex uint16

// InvalidSubtreeIndex is an invalid subtree index.
const InvalidSubtreeIndex SubtreeIndex = (1 << 16) - 1

// SubtreePointer is a pointer into the compressed representation of a
// subtree.
type SubtreePointer struct {
	Index SubtreeIndex
	Full  bool
	Valid bool
}

// MarshalBinary encodes a subtree pointer into binary form.
func (s *SubtreePointer) MarshalBinary() (data []byte, err error) {
	data = make([]byte, treePointerLen)
	binary.LittleEndian.PutUint16(data[:2], uint16(s.Index))
	if s.Full {
		data[treeIndexLen] = 1
	} else {
		data[treeIndexLen] = 0
	}
	return
}

// UnmarshalBinary decodes a binary marshaled subtree pointer.
func (s *SubtreePointer) UnmarshalBinary(data []byte) error {
	_, err := s.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled subtree pointer.
func (s *SubtreePointer) SizedUnmarshalBinary(data []byte) (int, error) {
	if len(data) < treePointerLen {
		return 0, node.ErrMalformedNode
	}
	if data[treeIndexLen] > 1 {
		return 0, node.ErrMalformedNode
	}
	s.Index = SubtreeIndex(binary.LittleEndian.Uint16(data[:treeIndexLen]))
	s.Full = data[treeIndexLen] > 0
	s.Valid = true
	return treePointerLen, nil
}

// Equal compares a subtree pointer with some other subtree pointer.
func (s *SubtreePointer) Equal(other *SubtreePointer) bool {
	return s.Index == other.Index && s.Full == other.Full
}

// InternalNodeSummary is a compressed (index-only) representation of an
// internal node.
type InternalNodeSummary struct {
	Label    node.Key
	LeafNode SubtreePointer
	Left     SubtreePointer
	Right    SubtreePointer

	LabelBitLength node.Depth
	invalid        bool
}

// MarshalBinary encodes an internal node summary into binary form.
func (s *InternalNodeSummary) MarshalBinary() (data []byte, err error) {
	var leafNode []byte
	var left []byte
	var right []byte

	if leafNode, err = s.LeafNode.MarshalBinary(); err != nil {
		return
	}
	if left, err = s.Left.MarshalBinary(); err != nil {
		return
	}
	if right, err = s.Right.MarshalBinary(); err != nil {
		return
	}
	data = make([]byte, node.DepthSize+len(s.Label)+len(leafNode)+len(left)+len(right))

	pos := 0
	copy(data[pos:pos+node.DepthSize], s.LabelBitLength.MarshalBinary()[:])
	pos += node.DepthSize

	copy(data[pos:pos+len(s.Label)], s.Label)
	pos += len(s.Label)

	copy(data[pos:pos+len(leafNode)], leafNode)
	pos += len(leafNode)

	copy(data[pos:pos+len(left)], left)
	pos += len(left)

	copy(data[pos:], right)

	return
}

// UnmarshalBinary decodes a binary marshaled internal node summary.
func (s *InternalNodeSummary) UnmarshalBinary(data []byte) error {
	_, err := s.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled internal node summary.
func (s *InternalNodeSummary) SizedUnmarshalBinary(data []byte) (int, error) {
	var labelLen int
	var leafNodeLen int
	var leftLen int
	var rightLen int
	var err error

	ds := 0
	pos := 0
	if ds, err = s.LabelBitLength.UnmarshalBinary(data[pos:]); err != nil {
		return 0, err
	}
	labelLen = s.LabelBitLength.ToBytes()
	pos += ds

	s.Label = make(node.Key, labelLen)
	copy(s.Label, data[pos:pos+labelLen])
	pos += labelLen

	leafNode := SubtreePointer{}
	if leafNodeLen, err = leafNode.SizedUnmarshalBinary(data[pos:]); err != nil {
		return 0, err
	}
	pos += leafNodeLen

	left := SubtreePointer{}
	if leftLen, err = left.SizedUnmarshalBinary(data[pos:]); err != nil {
		return 0, err
	}
	pos += leftLen

	right := SubtreePointer{}
	if rightLen, err = right.SizedUnmarshalBinary(data[pos:]); err != nil {
		return 0, err
	}
	pos += rightLen

	s.LeafNode = leafNode
	s.Left = left
	s.Right = right
	s.invalid = false
	return pos, nil
}

// Equal compares a node summary with some other node summary.
func (s *InternalNodeSummary) Equal(other *InternalNodeSummary) bool {
	return s.LeafNode.Equal(&other.LeafNode) && s.Left.Equal(&other.Left) && s.Right.Equal(&other.Right)
}

// Subtree is a compressed representation of a subtree.
type Subtree struct {
	Root SubtreePointer

	Summaries []InternalNodeSummary
	FullNodes []node.Node
}

func checkSubtreeIndex(idx int) (SubtreeIndex, error) {
	if idx >= int(InvalidSubtreeIndex) {
		return InvalidSubtreeIndex, ErrTooManyFullNodes
	}

	return SubtreeIndex(idx), nil
}

// AddSummary adds a new internal node summary to the subtree.
func (s *Subtree) AddSummary(ns InternalNodeSummary) (SubtreeIndex, error) {
	idx, err := checkSubtreeIndex(len(s.Summaries))
	if err != nil {
		return idx, err
	}
	s.Summaries = append(s.Summaries, ns)
	return idx, nil
}

// AddFullNode adds a new full node to the subtree.
func (s *Subtree) AddFullNode(n node.Node) (SubtreeIndex, error) {
	idx, err := checkSubtreeIndex(len(s.FullNodes))
	if err != nil {
		return idx, err
	}
	s.FullNodes = append(s.FullNodes, n)
	return idx, nil
}

// GetFullNodeAt retrieves a full node at a specific index.
//
// If the index has already been marked as used it returns an error.
func (s *Subtree) GetFullNodeAt(idx SubtreeIndex) (node.Node, error) {
	if idx == InvalidSubtreeIndex || int(idx) >= len(s.FullNodes) {
		return nil, ErrInvalidSubtreeIndex
	}
	node := s.FullNodes[idx]
	if node == nil {
		return nil, ErrInvalidSubtreeIndex
	}
	return node, nil
}

// GetSummaryAt retrieves an internal node summary at a specific index.
//
// If the index has already been marked as used it returns an error.
func (s *Subtree) GetSummaryAt(idx SubtreeIndex) (*InternalNodeSummary, error) {
	if idx == InvalidSubtreeIndex {
		return nil, nil
	}
	if int(idx) >= len(s.Summaries) {
		return nil, ErrInvalidSubtreeIndex
	}
	sum := s.Summaries[idx]
	if sum.invalid {
		return nil, ErrInvalidSubtreeIndex
	}
	return &sum, nil
}

// MarkUsed marks the given index as used.
func (s *Subtree) MarkUsed(ptr SubtreePointer) {
	if ptr.Full {
		s.FullNodes[ptr.Index] = nil
	} else if ptr.Index != InvalidSubtreeIndex {
		s.Summaries[ptr.Index].invalid = true
	}
}

// MarshalBinary encodes a subtree into binary form.
func (s *Subtree) MarshalBinary() (data []byte, err error) {
	if data, err = s.Root.MarshalBinary(); err != nil {
		return nil, err
	}

	scratch := make([]byte, treeIndexLen)

	binary.LittleEndian.PutUint16(scratch, uint16(len(s.Summaries)))
	data = append(data, scratch...)
	for _, summary := range s.Summaries {
		var serialized []byte
		if serialized, err = summary.MarshalBinary(); err != nil {
			return nil, err
		}
		data = append(data, serialized...)
	}

	binary.LittleEndian.PutUint16(scratch, uint16(len(s.FullNodes)))
	data = append(data, scratch...)
	for _, node := range s.FullNodes {
		var serialized []byte
		if serialized, err = node.MarshalBinary(); err != nil {
			return nil, err
		}
		data = append(data, serialized...)
	}
	return
}

// UnmarshalBinary decodes a binary marshaled subtree.
func (s *Subtree) UnmarshalBinary(data []byte) error {
	_, err := s.SizedUnmarshalBinary(data)
	return err
}

// SizedUnmarshalBinary decodes a binary marshaled subtree.
func (s *Subtree) SizedUnmarshalBinary(data []byte) (int, error) {
	// Size is at least the root pointer and two array lengths.
	if len(data) < treePointerLen+2*treeIndexLen {
		return 0, node.ErrMalformedNode
	}

	var rootPointer SubtreePointer
	var err error
	var offset int
	if offset, err = rootPointer.SizedUnmarshalBinary(data); err != nil {
		return 0, err
	}

	summaryCount := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	summaries := make([]InternalNodeSummary, summaryCount)
	for i := uint16(0); i < summaryCount; i++ {
		var summary InternalNodeSummary
		var summaryLen int
		if summaryLen, err = summary.SizedUnmarshalBinary(data[offset:]); err != nil {
			return 0, err
		}
		summaries[i] = summary
		offset += summaryLen
	}

	if len(data) < offset+treeIndexLen {
		return 0, node.ErrMalformedNode
	}
	nodeCount := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	nodes := make([]node.Node, nodeCount)
	for i := uint16(0); i < nodeCount; i++ {
		var nodeLen int
		if len(data) <= offset {
			return 0, node.ErrMalformedNode
		}
		switch data[offset] {
		case node.PrefixNilNode:
			nodes[i] = nil
			offset++
		case node.PrefixInternalNode:
			node := &node.InternalNode{}
			if nodeLen, err = node.SizedUnmarshalBinary(data[offset:]); err != nil {
				return 0, err
			}
			offset += nodeLen
			nodes[i] = node
		case node.PrefixLeafNode:
			node := &node.LeafNode{}
			if nodeLen, err = node.SizedUnmarshalBinary(data[offset:]); err != nil {
				return 0, err
			}
			offset += nodeLen
			nodes[i] = node
		default:
			return 0, node.ErrMalformedNode
		}
	}

	s.Root = rootPointer
	s.Summaries = summaries
	s.FullNodes = nodes

	return offset, nil
}

// Equal compares a subtree with some other subtree.
func (s *Subtree) Equal(other *Subtree) bool {
	if s == nil && other == nil {
		return true
	}
	if s == nil || other == nil {
		return false
	}
	if !s.Root.Equal(&other.Root) || len(s.Summaries) != len(other.Summaries) || len(s.FullNodes) != len(other.FullNodes) {
		return false
	}

	for i, summary := range s.Summaries {
		if !summary.Equal(&other.Summaries[i]) {
			return false
		}
	}
	for i, node := range s.FullNodes {
		if !node.Equal(other.FullNodes[i]) {
			return false
		}
	}
	return true
}
