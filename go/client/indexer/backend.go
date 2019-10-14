package indexer

import (
	"context"
	"errors"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
)

var (
	_ cbor.Marshaler   = (*Query)(nil)
	_ cbor.Unmarshaler = (*Query)(nil)
)

const (
	// maxQueryLimit is the maximum number of results to return.
	maxQueryLimit = 1000
)

// Condition is a query condition.
type Condition struct {
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
	Conditions []Condition `json:"conditions"`

	// Limit is the maximum number of results to return.
	//
	// A zero value means that the `maxQueryLimit` limit is used.
	Limit uint64 `json:"limit"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (q *Query) MarshalCBOR() []byte {
	return cbor.Marshal(q)
}

// UnmarshalCBOR decodes a CBOR marshaled query.
func (q *Query) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, q)
}

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

// Backend is an indexer backend.
type Backend interface {
	// Index indexes a list of transactions for the same block round of a given runtime.
	//
	// NOTE: Currently the indexer requires all transactions as well since it needs to
	//       expose a notion of a "transaction index within a block" which is hard to
	//       provide as batches can be merged in arbitrary order and the sequence can
	//       only be known after the fact.
	Index(
		ctx context.Context,
		runtimeID signature.PublicKey,
		round uint64,
		blockHash hash.Hash,
		txs []*transaction.Transaction,
		tags transaction.Tags,
	) error

	// QueryBlock queries the block index of a given runtime.
	QueryBlock(ctx context.Context, runtimeID signature.PublicKey, blockHash hash.Hash) (uint64, error)

	// QueryTxn queries the transaction index of a given runtime.
	QueryTxn(ctx context.Context, runtimeID signature.PublicKey, key, value []byte) (uint64, hash.Hash, uint32, error)

	// QueryTxnByIndex queries the transaction index of a given runtime for a
	// specific transaction hash identified by its block round and index.
	QueryTxnByIndex(ctx context.Context, runtimeID signature.PublicKey, round uint64, index uint32) (hash.Hash, error)

	// QueryTxns queries the transaction index of a given runtime with a complex
	// query and returns multiple results.
	//
	// If a backend does not support this method it may return ErrUnsupported.
	QueryTxns(ctx context.Context, runtimeID signature.PublicKey, query Query) (Results, error)

	// WaitBlockIndexed waits for a block to be indexed by the indexer.
	WaitBlockIndexed(ctx context.Context, runtimeID signature.PublicKey, round uint64) error

	// Prune removes entries associated with the given round.
	Prune(ctx context.Context, runtimeID signature.PublicKey, round uint64) error

	// Stops the backend.
	//
	// After this method is called, no further operations should be done.
	Stop()
}

type indexNotification struct {
	runtimeID signature.PublicKey
	round     uint64
}

type backendCommon struct {
	blockIndexedNotifier *pubsub.Broker
}

func (b *backendCommon) WaitBlockIndexed(ctx context.Context, runtimeID signature.PublicKey, round uint64) error {
	sub := b.blockIndexedNotifier.Subscribe()
	defer sub.Close()

	ch := make(chan *indexNotification)
	sub.Unwrap(ch)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case n := <-ch:
			if n == nil {
				return errors.New("indexer: channel closed while waiting for index notification")
			}

			if n.runtimeID.Equal(runtimeID) && n.round >= round {
				return nil
			}
		}
	}
}

func newBackendCommon() backendCommon {
	return backendCommon{
		blockIndexedNotifier: pubsub.NewBroker(true),
	}
}
