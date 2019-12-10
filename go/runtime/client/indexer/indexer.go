// Package indexer implements the block/transaction tag indexer.
package indexer

import (
	"context"
	"errors"
	"time"

	"github.com/cenkalti/backoff"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/service"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/runtime/history"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
)

const (
	storageRequestTimeout = 5 * time.Second
	storageRetryTimeout   = 120 * time.Second
)

var (
	// ErrTagTooLong is the error when either key or value is too long.
	ErrTagTooLong = errors.New("indexer: tag too long to process")
	// ErrCorrupted is the error when index corruption is detected.
	ErrCorrupted = errors.New("indexer: index corrupted")
	// ErrUnsupported is the error when the given method is not supported.
	ErrUnsupported = errors.New("indexer: method not supported")

	_ history.PruneHandler = (*pruneHandler)(nil)
)

type pruneHandler struct {
	logger    *logging.Logger
	backend   Backend
	runtimeID signature.PublicKey
}

func (p *pruneHandler) Prune(ctx context.Context, rounds []uint64) error {
	// New blocks to prune from the index.
	for _, round := range rounds {
		if err := p.backend.Prune(ctx, p.runtimeID, round); err != nil {
			p.logger.Error("failed to prune index",
				"err", err,
				"round", round,
			)
			return err
		}
	}

	return nil
}

// Service is an indexer service.
type Service struct {
	service.BaseBackgroundService

	runtime  runtimeRegistry.Runtime
	backend  Backend
	roothash roothash.Backend
	storage  storage.Backend

	stopCh chan struct{}
}

func (s *Service) worker() {
	defer s.BaseBackgroundService.Stop()

	ctx := context.TODO()

	s.Logger.Info("started indexer for runtime")

	// Start watching roothash blocks.
	blocksCh, blocksSub, err := s.roothash.WatchBlocks(s.runtime.ID())
	if err != nil {
		s.Logger.Error("failed to subscribe to roothash blocks",
			"err", err,
		)
		return
	}
	defer blocksSub.Close()

	for {
		select {
		case <-s.stopCh:
			s.Logger.Info("stop requested, terminating indexer")
			return
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
				off := backoff.NewExponentialBackOff()
				off.MaxElapsedTime = storageRetryTimeout

				err = backoff.Retry(func() error {
					bctx, cancel := context.WithTimeout(ctx, storageRequestTimeout)
					defer cancel()

					ioRoot := storage.Root{
						Namespace: blk.Header.Namespace,
						Round:     blk.Header.Round,
						Hash:      blk.Header.IORoot,
					}

					tree := transaction.NewTree(s.storage, ioRoot)
					defer tree.Close()

					txs, err = tree.GetTransactions(bctx)
					if err != nil {
						return err
					}

					tags, err = tree.GetTags(bctx)
					if err != nil {
						return err
					}

					return nil
				}, off)

				if err != nil {
					s.Logger.Error("can't get I/O root from storage",
						"err", err,
						"round", blk.Header.Round,
					)
					continue
				}
			}

			if err = s.backend.Index(
				ctx,
				s.runtime.ID(),
				blk.Header.Round,
				blk.Header.EncodedHash(),
				txs,
				tags,
			); err != nil {
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
	runtime runtimeRegistry.Runtime,
	backend Backend,
	roothash roothash.Backend,
	storage storage.Backend,
) (*Service, error) {
	s := &Service{
		BaseBackgroundService: *service.NewBaseBackgroundService("client/indexer"),
		runtime:               runtime,
		backend:               backend,
		roothash:              roothash,
		storage:               storage,
		stopCh:                make(chan struct{}),
	}
	s.Logger = s.Logger.With("runtime_id", s.runtime.ID().String())

	// Register prune handler.
	runtime.History().Pruner().RegisterHandler(&pruneHandler{
		logger:    s.Logger,
		backend:   s.backend,
		runtimeID: s.runtime.ID(),
	})

	return s, nil
}
