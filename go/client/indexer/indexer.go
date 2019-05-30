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
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
)

const (
	storageTimeout = 5 * time.Second
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
)

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

			if err = s.backend.Prune(context.TODO(), pruned.RuntimeID, pruned.Round); err != nil {
				logger.Error("failed to prune index",
					"round", pruned.Round,
				)
				continue
			}
		case blk := <-blocksCh:
			// New blocks to index.
			var tags []runtime.Tag

			// Fetch tags from storage.
			if !blk.Header.IORoot.IsEmpty() {
				ctx, cancel := context.WithTimeout(context.TODO(), storageTimeout)

				var tree *urkel.Tree
				tree, err = urkel.NewWithRoot(ctx, s.storage, nil, blk.Header.IORoot)
				if err != nil {
					logger.Error("can't get block tags from storage",
						"err", err,
						"round", blk.Header.Round,
					)
					cancel()
					continue
				}

				var rawTags []byte
				rawTags, err = tree.Get(ctx, block.IoKeyTags)
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

			if err = s.backend.Index(context.TODO(), s.runtimeID, blk.Header.Round, tags); err != nil {
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
