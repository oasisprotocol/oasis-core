package grpc

import (
	"google.golang.org/grpc/encoding"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

// cborCodecName is the name of the CBOR gRPC codec.
const cborCodecName = "cbor"

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
	return cborCodecName
}

func (c *CBORCodec) String() string {
	return c.Name()
}

func init() {
	encoding.RegisterCodec(&CBORCodec{})
}
