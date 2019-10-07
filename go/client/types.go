package client

import (
	"math"

	"github.com/oasislabs/ekiden/go/client/indexer"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
)

var (
	_ cbor.Marshaler   = (*TxnResult)(nil)
	_ cbor.Unmarshaler = (*TxnResult)(nil)
)

const (
	// EndpointKeyManager is the key manager EnclaveRPC endpoint.
	EndpointKeyManager = "key-manager"

	// RoundLatest is a special round number always referring to the latest round.
	RoundLatest uint64 = math.MaxUint64
)

// Query is an indexer query.
type Query = indexer.Query

// QueryCondition is an indexer query condition.
type QueryCondition = indexer.Condition

// TxnResult is the transaction query result.
type TxnResult struct {
	Block     *block.Block `json:"block"`
	BlockHash hash.Hash    `json:"block_hash"`
	Index     uint32       `json:"index"`
	Input     []byte       `json:"input"`
	Output    []byte       `json:"output"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (r *TxnResult) MarshalCBOR() []byte {
	return cbor.Marshal(r)
}

// UnmarshalCBOR decodes a CBOR marshaled query result.
func (r *TxnResult) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, r)
}
