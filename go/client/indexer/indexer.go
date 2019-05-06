// Package indexer implements the block/transaction tag indexer.
package indexer

import (
	"context"
	"errors"
	"time"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/runtime"
	"github.com/oasislabs/ekiden/go/common/service"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

const (
	storageTimeout = 5 * time.Second
	// maxQueryLimit is the maximum number of results to return.
	maxQueryLimit = 1000
)

var (
	// ErrTagTooLong is the error when either key or value is too long.
	ErrTagTooLong = errors.New("indexer: tag too long to process")
	// ErrNotFound is the error when no entries are found.
	ErrNotFound = errors.New("indexer: no entries found")
	// ErrCorrupted is the error when index corruption is detected.
	ErrCorrupted = errors.New("indexer: index corrupted")
	// ErrUnsupported is the error when the given method is not supported.
	ErrUnsupported = errors.New("indexer: method not supported")

	// TagBlockHash is the tag used for storing the Ekiden block hash.
	TagBlockHash = []byte("hblk")

	_ cbor.Marshaler   = (*Query)(nil)
	_ cbor.Unmarshaler = (*Query)(nil)
)

// Condition is a query condition.
type Condition struct {
	// Key is the tag key that should be matched.
	Key []byte `codec:"key"`
	// Values are a list of tag values that the given tag key should
	// have. They are combined using an OR query which means that any
	// of the values will match.
	Values [][]byte `codec:"values"`
}

// Query is a complex query against the index.
type Query struct {
	// RoundMin is an optional minimum round (inclusive).
	RoundMin *uint64 `codec:"round_min"`
	// RoundMax is an optional maximum round (exclusive).
	RoundMax *uint64 `codec:"round_max"`

	// Conditions are the query conditions.
	//
	// They are combined using an AND query which means that all of
	// the conditions must be satisfied for an item to match.
	Conditions []Condition `codec:"conditions"`

	// Limit is the maximum number of results to return.
	Limit *uint64 `codec:"limit"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (q *Query) MarshalCBOR() []byte {
	return cbor.Marshal(q)
}

// UnmarshalCBOR decodes a CBOR marshaled query.
func (q *Query) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, q)
}

// Results are query results.
//
// Map key is the round number and value is a list of transaction indexes
// that match the query.
type Results map[uint64][]int32

// Backend is an indexer backend.
type Backend interface {
	// Index indexes a list of tags for the same block round of a given runtime.
	Index(runtimeID signature.PublicKey, round uint64, tags []runtime.Tag) error

	// QueryBlock queries the block index of a given runtime.
	QueryBlock(ctx context.Context, runtimeID signature.PublicKey, key, value []byte) (uint64, error)

	// QueryTxn queries the transaction index of a given runtime.
	QueryTxn(ctx context.Context, runtimeID signature.PublicKey, key, value []byte) (uint64, uint32, error)

	// QueryTxns queries the transaction index of a given runtime with a complex
	// query and returns multiple results.
	//
	// If a backend does not support this method it may return ErrUnsupported.
	QueryTxns(ctx context.Context, runtimeID signature.PublicKey, query Query) (Results, error)

	// Prune removes entries associated with the given round.
	Prune(runtimeID signature.PublicKey, round uint64) error

	// Stops the backend.
	//
	// After this method is called, no further operations should be done.
	Stop()
}

// Service is an indexer service.
type Service struct {
	service.BaseBackgroundService

	runtimeID signature.PublicKey
	backend   Backend
	roothash  roothash.Backend
	storage   storage.Backend

	stopCh chan struct{}
}

func (s *Service) worker() {
	defer s.BaseBackgroundService.Stop()

	// Start watching roothash blocks.
	blocksCh, blocksSub, err := s.roothash.WatchBlocks(s.runtimeID)
	if err != nil {
		s.Logger.Error("failed to subscribe to roothash blocks",
			"err", err,
		)
		return
	}
	defer blocksSub.Close()

	// Start watching pruned blocks.
	prunedCh, pruneSub, err := s.roothash.WatchPrunedBlocks()
	if err != nil {
		s.Logger.Error("failed to subscribe to pruned roothash blocks",
			"err", err,
		)
		return
	}
	defer pruneSub.Close()

	logger := s.Logger.With("runtime_id", s.runtimeID.String())
	logger.Info("started indexer for runtime")

	for {
		select {
		case <-s.stopCh:
			logger.Info("stop requested, terminating indexer")
			return
		case pruned := <-prunedCh:
			// New blocks to prune from the index.
			if !s.runtimeID.Equal(pruned.RuntimeID) {
				continue
			}

			if err = s.backend.Prune(pruned.RuntimeID, pruned.Round); err != nil {
				logger.Error("failed to prune index",
					"round", pruned.Round,
				)
				continue
			}
		case blk := <-blocksCh:
			// New blocks to index.
			var tags []runtime.Tag

			// Fetch tags from storage.
			if !blk.Header.TagHash.IsEmpty() {
				ctx, cancel := context.WithTimeout(context.Background(), storageTimeout)

				var rawTags []byte
				rawTags, err = s.storage.Get(ctx, storage.Key(blk.Header.TagHash))
				cancel()
				if err != nil {
					logger.Error("can't get block tags from storage",
						"err", err,
						"round", blk.Header.Round,
					)
					continue
				}

				err = cbor.Unmarshal(rawTags, &tags)
				if err != nil {
					logger.Error("can't unmarshal tags from cbor",
						"err", err,
						"round", blk.Header.Round,
					)
					continue
				}
			}

			// Include block hash tag.
			blockHash := blk.Header.EncodedHash()
			tags = append(tags, runtime.Tag{
				TxnIndex: runtime.TagTxnIndexBlock,
				Key:      TagBlockHash,
				Value:    blockHash[:],
			})

			if err = s.backend.Index(s.runtimeID, blk.Header.Round, tags); err != nil {
				logger.Error("failed to index tags",
					"err", err,
					"round", blk.Header.Round,
				)
				continue
			}
		}
	}
}

func (s *Service) Start() error {
	go s.worker()
	return nil
}

func (s *Service) Stop() {
	close(s.stopCh)
}

// New creates a new indexer service.
func New(
	id signature.PublicKey,
	backend Backend,
	roothash roothash.Backend,
	storage storage.Backend,
) (*Service, error) {
	svc := service.NewBaseBackgroundService("client/indexer")
	return &Service{
		BaseBackgroundService: *svc,
		runtimeID:             id,
		backend:               backend,
		roothash:              roothash,
		storage:               storage,
		stopCh:                make(chan struct{}),
	}, nil
}
