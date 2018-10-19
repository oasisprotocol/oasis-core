package api

import (
	"github.com/oasislabs/ekiden/go/common/cbor"

	pbRoothash "github.com/oasislabs/ekiden/go/grpc/roothash"
)

var (
	_ cbor.Marshaler   = (*Block)(nil)
	_ cbor.Unmarshaler = (*Block)(nil)
)

// Block is an Oasis block.
type Block struct {
	// Header is the block header.
	Header Header `codec:"header"`
}

// FromProto deserializes a protobuf into a block.
//
// WARNING: The block is not guaranteed to be internally consistent.
func (b *Block) FromProto(pb *pbRoothash.Block) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	if err := b.Header.FromProto(pb.GetHeader()); err != nil {
		return err
	}

	return nil
}

// ToProto serializes a protobuf into a block.
func (b *Block) ToProto() *pbRoothash.Block {
	resp := new(pbRoothash.Block)
	resp.Header = b.Header.ToProto()

	return resp
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (b *Block) MarshalCBOR() []byte {
	return cbor.Marshal(b)
}

// UnmarshalCBOR decodes a CBOR marshaled block.
func (b *Block) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, b)
}
