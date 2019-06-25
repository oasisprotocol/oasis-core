package urkel

import (
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

var (
	_ SizedBinaryUnmarshaler = (*node.InternalNode)(nil)
	_ SizedBinaryUnmarshaler = (*node.LeafNode)(nil)
	_ SizedBinaryUnmarshaler = (*node.Value)(nil)
)

// SizedBinaryUnmarshaler defines an unmarshaling method that
// returns the number of bytes consumed.
type SizedBinaryUnmarshaler interface {
	SizedUnmarshalBinary(data []byte) (int, error)
}
