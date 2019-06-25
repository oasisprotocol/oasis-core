package urkel

import (
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

var (
	_ SizedBinaryUnmarshaler = (*internal.InternalNode)(nil)
	_ SizedBinaryUnmarshaler = (*internal.LeafNode)(nil)
	_ SizedBinaryUnmarshaler = (*internal.Value)(nil)
)

// SizedBinaryUnmarshaler defines an unmarshaling method that
// returns the number of bytes consumed.
type SizedBinaryUnmarshaler interface {
	SizedUnmarshalBinary(data []byte) (int, error)
}

// NodeUnmarshalBinary unmarshals a node of arbitrary type.
func NodeUnmarshalBinary(bytes []byte) (internal.Node, error) {
	return internal.NodeUnmarshalBinary(bytes)
}
