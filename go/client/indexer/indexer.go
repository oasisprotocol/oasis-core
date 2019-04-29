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
	// maxKeyValueLength is the maximum length of keys and values.
	maxKeyValueLength = 255
)

var (
	// ErrTagTooLong is the error when either key or value is too long.
	ErrTagTooLong = errors.New("indexer: tag too long to process")
	// ErrNotFound is the error when no entries are found.
	ErrNotFound = errors.New("indexer: no entries found")

	// TagBlockHash is the tag used for storing the Ekiden block hash.
	TagBlockHash = []byte("hblk")
)

// Backend is an indexer backend.
type Backend interface {
	// Index indexes a list of tags for the same block round of a given runtime.
	Index(runtimeID signature.PublicKey, round uint64, tags []runtime.Tag) error

	// QueryBlock queries the block index of a given runtime.
	QueryBlock(ctx context.Context, runtimeID signature.PublicKey, key, value []byte) (uint64, error)

	// QueryTxn queries the transaction index of a given runtime.
	QueryTxn(ctx context.Context, runtimeID signature.PublicKey, key, value []byte) (uint64, uint32, error)

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
	blocksCh, sub, err := s.roothash.WatchBlocks(s.runtimeID)
	if err != nil {
		s.Logger.Error("failed to subscribe to roothash blocks",
			"err", err,
		)
		return
	}
	defer sub.Close()

	s.Logger.Info("started indexer for runtime",
		"runtime_id", s.runtimeID.String(),
	)

	for {
		select {
		case <-s.stopCh:
			s.Logger.Info("stop requested, terminating indexer")
			return
		case blk := <-blocksCh:
			var tags []runtime.Tag

			// Fetch tags from storage.
			if !blk.Header.TagHash.IsEmpty() {
				ctx, cancel := context.WithTimeout(context.Background(), storageTimeout)

				var rawTags []byte
				rawTags, err = s.storage.Get(ctx, storage.Key(blk.Header.TagHash))
				cancel()
				if err != nil {
					s.Logger.Error("can't get block tags from storage",
						"err", err,
						"round", blk.Header.Round,
					)
					continue
				}

				err = cbor.Unmarshal(rawTags, &tags)
				if err != nil {
					s.Logger.Error("can't unmarshal tags from cbor",
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
				s.Logger.Error("failed to index tags",
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
