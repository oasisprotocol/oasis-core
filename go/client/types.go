package client

import (
	"math"

	"github.com/oasislabs/oasis-core/go/client/indexer"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
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
