package syncer

import (
	"errors"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
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

// InternalNodeSummary is a compressed (index-only) representation of an
// internal node.
type InternalNodeSummary struct {
	invalid bool

	Left  SubtreePointer
	Right SubtreePointer
}

// Subtree is a compressed representation of a subtree.
type Subtree struct {
	Root SubtreePointer

	Summaries []InternalNodeSummary
	FullNodes []internal.Node
}

func checkSubtreeIndex(idx int) (SubtreeIndex, error) {
	si := SubtreeIndex(idx)
	if si >= InvalidSubtreeIndex {
		return InvalidSubtreeIndex, ErrTooManyFullNodes
	}

	return si, nil
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
func (s *Subtree) AddFullNode(n internal.Node) (SubtreeIndex, error) {
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
func (s *Subtree) GetFullNodeAt(idx SubtreeIndex) (internal.Node, error) {
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
