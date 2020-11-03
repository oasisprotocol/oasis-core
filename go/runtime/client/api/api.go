package api

import (
	"context"
	"math"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
)

const (
	// ModuleName is the runtime client module name.
	ModuleName = "runtime/client"

	// RoundLatest is a special round number always referring to the latest round.
	RoundLatest uint64 = math.MaxUint64
)

var (
	// ErrNotFound is an error returned when the item is not found.
	ErrNotFound = errors.New(ModuleName, 1, "client: not found")
	// ErrInternal is an error returned when an unspecified internal error occurs.
	ErrInternal = errors.New(ModuleName, 2, "client: internal error")
	// ErrTransactionExpired is an error returned when transaction expired.
	ErrTransactionExpired = errors.New(ModuleName, 3, "client: transaction expired")
)

// RuntimeClient is the runtime client interface.
type RuntimeClient interface {
	enclaverpc.Transport

	// SubmitTx submits a transaction to the runtime transaction scheduler.
	SubmitTx(ctx context.Context, request *SubmitTxRequest) ([]byte, error)

	// GetGenesisBlock returns the genesis block.
	GetGenesisBlock(ctx context.Context, runtimeID common.Namespace) (*block.Block, error)

	// GetBlock fetches the given runtime block.
	GetBlock(ctx context.Context, request *GetBlockRequest) (*block.Block, error)

	// GetBlockByHash fetches the given runtime block by its block hash.
	GetBlockByHash(ctx context.Context, request *GetBlockByHashRequest) (*block.Block, error)

	// GetTx fetches the given runtime transaction.
	GetTx(ctx context.Context, request *GetTxRequest) (*TxResult, error)

	// GetTxByBlockHash fetches the given rutnime transaction where the
	// block is identified by its hash instead of its round number.
	GetTxByBlockHash(ctx context.Context, request *GetTxByBlockHashRequest) (*TxResult, error)

	// GetTxs fetches all runtime transactions in a given block.
	GetTxs(ctx context.Context, request *GetTxsRequest) ([][]byte, error)

	// QueryTx queries the indexer for a specific runtime transaction.
	QueryTx(ctx context.Context, request *QueryTxRequest) (*TxResult, error)

	// QueryTxs queries the indexer for specific runtime transactions.
	QueryTxs(ctx context.Context, request *QueryTxsRequest) ([]*TxResult, error)

	// WatchBlocks subscribes to blocks for a specific runtimes.
	WatchBlocks(ctx context.Context, runtimeID common.Namespace) (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error)

	// WaitBlockIndexed waits for a runtime block to be indexed by the indexer.
	WaitBlockIndexed(ctx context.Context, request *WaitBlockIndexedRequest) error

	// Cleanup cleans up the backend.
	Cleanup()
}

// SubmitTxRequest is a SubmitTx request.
type SubmitTxRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Data      []byte           `json:"data"`
}

// GetBlockRequest is a GetBlock request.
type GetBlockRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Round     uint64           `json:"round"`
}

// GetBlockByHashRequest is a GetBlockByHash request.
type GetBlockByHashRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	BlockHash hash.Hash        `json:"block_hash"`
}

// TxResult is the transaction query result.
type TxResult struct {
	Block  *block.Block `json:"block"`
	Index  uint32       `json:"index"`
	Input  []byte       `json:"input"`
	Output []byte       `json:"output"`
}

// GetTxRequest is a GetTx request.
type GetTxRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Round     uint64           `json:"round"`
	Index     uint32           `json:"index"`
}

// GetTxByBlockHashRequest is a GetTxByBlockHash request.
type GetTxByBlockHashRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	BlockHash hash.Hash        `json:"block_hash"`
	Index     uint32           `json:"index"`
}

// GetTxsRequest is a GetTxs request.
type GetTxsRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Round     uint64           `json:"round"`
	IORoot    hash.Hash        `json:"io_root"`
}

// QueryTxRequest is a QueryTx request.
type QueryTxRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Key       []byte           `json:"key"`
	Value     []byte           `json:"value"`
}

// QueryCondition is a query condition.
type QueryCondition struct {
	// Key is the tag key that should be matched.
	Key []byte `json:"key"`
	// Values are a list of tag values that the given tag key should
	// have. They are combined using an OR query which means that any
	// of the values will match.
	Values [][]byte `json:"values"`
}

// Query is a complex query against the index.
type Query struct {
	// RoundMin is an optional minimum round (inclusive).
	RoundMin uint64 `json:"round_min"`
	// RoundMax is an optional maximum round (inclusive).
	//
	// A zero value means that there is no upper limit.
	RoundMax uint64 `json:"round_max"`

	// Conditions are the query conditions.
	//
	// They are combined using an AND query which means that all of
	// the conditions must be satisfied for an item to match.
	Conditions []QueryCondition `json:"conditions"`

	// Limit is the maximum number of results to return.
	//
	// A zero value means that the `maxQueryLimit` limit is used.
	Limit uint64 `json:"limit"`
}

// QueryTxsRequest is a QueryTxs request.
type QueryTxsRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Query     Query            `json:"query"`
}

// WaitBlockIndexedRequest is a WaitBlockIndexed request.
type WaitBlockIndexedRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Round     uint64           `json:"round"`
}
