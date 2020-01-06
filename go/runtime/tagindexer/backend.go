package tagindexer

import (
	"context"
	"errors"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/runtime/client/api"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
)

const (
	// maxQueryLimit is the maximum number of results to return.
	maxQueryLimit = 1000
)

var (
	// ErrTagTooLong is the error when either key or value is too long.
	ErrTagTooLong = errors.New("tagindexer: tag too long to process")
	// ErrCorrupted is the error when index corruption is detected.
	ErrCorrupted = errors.New("tagindexer: index corrupted")

	errNopBackend = errors.New("tagindexer: tag indexer is disabled")
)

// Result is a query result.
type Result struct {
	// TxHash is the hash of the matched transaction.
	TxHash hash.Hash
	// TxIndex is the index of the matched transaction within the block.
	TxIndex uint32
}

// Results are query results.
//
// Map key is the round number and value is a list of transaction hashes
// that match the query.
type Results map[uint64][]Result

// BackendFactory is the tag indexer backend factory interface.
type BackendFactory func(dataDir string, runtimeID common.Namespace) (Backend, error)

// QueryableBackend is the read-only tag indexer backend interface.
type QueryableBackend interface {
	// QueryBlock queries the block tag index.
	QueryBlock(ctx context.Context, blockHash hash.Hash) (uint64, error)

	// QueryTxn queries the transaction tag index.
	QueryTxn(ctx context.Context, key, value []byte) (uint64, hash.Hash, uint32, error)

	// QueryTxnByIndex queries the transaction tag index for a specific transaction hash
	// identified by its block round and index.
	QueryTxnByIndex(ctx context.Context, round uint64, index uint32) (hash.Hash, error)

	// QueryTxns queries the transaction tag index of a given runtime with a complex
	// query and returns multiple results.
	//
	// If a backend does not support this method it may return ErrUnsupported.
	QueryTxns(ctx context.Context, query api.Query) (Results, error)

	// WaitBlockIndexed waits for a block to be indexed by the indexer.
	WaitBlockIndexed(ctx context.Context, round uint64) error
}

// Backend is the tag indexer backend interface.
type Backend interface {
	QueryableBackend

	// Index indexes a list of transactions for the same block round of a given runtime.
	//
	// NOTE: Currently the indexer requires all transactions as well since it needs to
	//       expose a notion of a "transaction index within a block" which is hard to
	//       provide as batches can be merged in arbitrary order and the sequence can
	//       only be known after the fact.
	Index(
		ctx context.Context,
		round uint64,
		blockHash hash.Hash,
		txs []*transaction.Transaction,
		tags transaction.Tags,
	) error

	// Prune removes entries associated with the given round.
	Prune(ctx context.Context, round uint64) error

	// Close closes the backend.
	//
	// After this method is called, no further operations should be done.
	Close()
}

type nopBackend struct {
}

func (n *nopBackend) Index(
	ctx context.Context,
	round uint64,
	blockHash hash.Hash,
	txs []*transaction.Transaction,
	tags transaction.Tags,
) error {
	return nil
}

func (n *nopBackend) Prune(ctx context.Context, round uint64) error {
	return nil
}

func (n *nopBackend) QueryBlock(ctx context.Context, blockHash hash.Hash) (uint64, error) {
	return 0, errNopBackend
}

func (n *nopBackend) QueryTxn(ctx context.Context, key, value []byte) (uint64, hash.Hash, uint32, error) {
	return 0, hash.Hash{}, 0, errNopBackend
}

func (n *nopBackend) QueryTxnByIndex(ctx context.Context, round uint64, index uint32) (hash.Hash, error) {
	return hash.Hash{}, errNopBackend
}

func (n *nopBackend) QueryTxns(ctx context.Context, query api.Query) (Results, error) {
	return nil, errNopBackend
}

func (n *nopBackend) WaitBlockIndexed(ctx context.Context, round uint64) error {
	return errNopBackend
}

func (n *nopBackend) Close() {
}

// NewNopBackend creates a new no-op backend that doesn't perform any indexing.
func NewNopBackend() BackendFactory {
	return func(string, common.Namespace) (Backend, error) {
		return &nopBackend{}, nil
	}
}
