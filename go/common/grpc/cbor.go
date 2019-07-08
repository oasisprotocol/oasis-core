package grpc

import (
	"github.com/oasislabs/ekiden/go/common/cbor"
)

// CBORCodec implements gRPC's encoding.Codec interface.
type CBORCodec struct {
}

func (c *CBORCodec) Marshal(v interface{}) ([]byte, error) {
	return cbor.Marshal(v), nil
}

func (c *CBORCodec) Unmarshal(data []byte, v interface{}) error {
	return cbor.Unmarshal(data, v)
}

func (c *CBORCodec) Name() string {
	return "CBORCodec"
}

func (c *CBORCodec) String() string {
	return c.Name()
}
