package mkvs

import (
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

var (
	_ SizedBinaryUnmarshaler = (*node.InternalNode)(nil)
	_ SizedBinaryUnmarshaler = (*node.LeafNode)(nil)
)

// SizedBinaryUnmarshaler defines an unmarshaling method that
// returns the number of bytes consumed.
type SizedBinaryUnmarshaler interface {
	SizedUnmarshalBinary(data []byte) (int, error)
}
