// Package indexer implements the block/transaction tag indexer.
package indexer

import (
	"context"
	"errors"
	"time"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/service"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/runtime/transaction"
	storage "github.com/oasislabs/ekiden/go/storage/api"
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

	logger := s.Logger.With("runtime_id", s.runtimeID.String())
	logger.Info("started indexer for runtime")

	// If using a storage client, it should watch the configured runtimes.
	if storageClient, ok := s.storage.(storage.ClientBackend); ok {
		if err := storageClient.WatchRuntime(s.runtimeID); err != nil {
			logger.Warn("indexer: error watching storage runtime, expected if using cachingclient/metricswrapper with local backend",
				"err", err,
			)
		}
	} else {
		logger.Info("not watching storage runtime since not using a storage client backend")
	}

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
		case annBlk := <-blocksCh:
			// New blocks to index.
			blk := annBlk.Block

			// Fetch transactions from storage.
			//
			// NOTE: Currently the indexer requires all transactions as well since it needs to
			//       expose a notion of a "transaction index within a block" which is hard to
			//       provide as batches can be merged in arbitrary order and the sequence can
			//       only be known after the fact.
			var txs []*transaction.Transaction
			var tags transaction.Tags
			if !blk.Header.IORoot.IsEmpty() {
				err = func() error {
					ctx, cancel := context.WithTimeout(context.TODO(), storageTimeout)
					defer cancel()

					ioRoot := storage.Root{
						Namespace: blk.Header.Namespace,
						Round:     blk.Header.Round,
						Hash:      blk.Header.IORoot,
					}

					var tree *transaction.Tree
					tree, err = transaction.NewTree(ctx, s.storage, ioRoot)
					if err != nil {
						return err
					}
					defer tree.Close()

					txs, err = tree.GetTransactions(ctx)
					if err != nil {
						return err
					}

					tags, err = tree.GetTags(ctx)
					if err != nil {
						return err
					}

					return nil
				}()
				if err != nil {
					logger.Error("can't get I/O root from storage",
						"err", err,
						"round", blk.Header.Round,
					)
					continue
				}
			}

			if err = s.backend.Index(
				context.TODO(),
				s.runtimeID,
				blk.Header.Round,
				blk.Header.EncodedHash(),
				txs,
				tags,
			); err != nil {
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
