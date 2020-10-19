// Package simple implements a simple batching transaction scheduler.
package simple

import (
	"fmt"
	"sync/atomic"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
	txpool "github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
	mapp "github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/map"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/orderedmap"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/queue"
)

const (
	// Name of the scheduler.
	Name = registry.TxnSchedulerSimple
)

type scheduler struct {
	logger *logging.Logger

	txPool        txpool.TxPool
	maxTxPoolSize uint64

	dispatcher         api.TransactionDispatcher
	dispatchInProgress uint32
}

func (s *scheduler) scheduleBatch(force bool) error {
	if !atomic.CompareAndSwapUint32(&s.dispatchInProgress, 0, 1) {
		// Dispatch already in progress.
		return nil
	}
	defer atomic.StoreUint32(&s.dispatchInProgress, 0)

	batch := s.txPool.GetBatch(force)
	if len(batch) > 0 {
		// Try to dispatch batch.
		if err := s.dispatcher.Dispatch(batch); err != nil {
			return err
		}
	}

	return nil
}

func (s *scheduler) ScheduleTx(tx []byte) error {
	if err := s.txPool.Add(tx); err != nil {
		// Return success in case of duplicate calls to avoid the client
		// mistaking this for an actual error.
		if err == txpool.ErrCallAlreadyExists {
			s.logger.Warn("ignoring duplicate call",
				"batch", tx,
			)
		} else {
			return err
		}
	}

	// Try scheduling a batch.
	if err := s.scheduleBatch(false); err != nil {
		// XXX: Log a warning here as the expected common failures are
		// whenever we try dispatching a batch and we are not the scheduler,
		// or when another batch is being processed.
		s.logger.Warn("failed scheduling a batch",
			"err", err,
		)
	}

	return nil
}

// AppendTxBatch appends a batch of transactions.
//
// Transactions that fail checks are skipped, not affecting the insertion of
// other transactions. If any transaction fails a check a non-nil error is
// returned.
// Aditionally this method does not try to schedule the transactions after the
// insert is finished, and is as such suited for reinserting transactions after
// a failed batch scheduling/processing.
func (s *scheduler) AppendTxBatch(batch [][]byte) error {
	return s.txPool.AddBatch(batch)
}

func (s *scheduler) RemoveTxBatch(tx [][]byte) error {
	return s.txPool.RemoveBatch(tx)
}

func (s *scheduler) Flush(force bool) error {
	// Schedule a batch.
	if err := s.scheduleBatch(force); err != nil {
		// XXX: Log a warning here as the expected common failures are
		// whenever we try dispatching a batch and we are not the scheduler,
		// or when another batch is being processed.
		s.logger.Warn("failed scheduling a batch",
			"err", err,
		)
		return err
	}

	return nil
}

func (s *scheduler) UnscheduledSize() uint64 {
	return s.txPool.Size()
}

func (s *scheduler) IsQueued(id hash.Hash) bool {
	return s.txPool.IsQueued(id)
}

func (s *scheduler) Clear() {
	s.txPool.Clear()
}

func (s *scheduler) Initialize(td api.TransactionDispatcher) error {
	s.dispatcher = td

	return nil
}

func (s *scheduler) IsInitialized() bool {
	return s.dispatcher != nil
}

func (s *scheduler) UpdateParameters(params registry.TxnSchedulerParameters) error {
	if params.Algorithm != Name {
		return fmt.Errorf("unexpected transaction scheduling algorithm: %s", params.Algorithm)
	}
	if err := s.txPool.UpdateConfig(txpool.Config{
		MaxBatchSize:      params.MaxBatchSize,
		MaxBatchSizeBytes: params.MaxBatchSizeBytes,
		MaxPoolSize:       s.maxTxPoolSize,
	}); err != nil {
		return fmt.Errorf("error updating parameters: %w", err)
	}
	return nil
}

func (s *scheduler) Name() string {
	return Name
}

// New creates a new simple scheduler.
func New(txPoolImpl string, maxTxPoolSize uint64, params registry.TxnSchedulerParameters) (api.Scheduler, error) {
	if params.Algorithm != Name {
		return nil, fmt.Errorf("unexpected transaction scheduling algorithm: %s", params.Algorithm)
	}

	poolCfg := txpool.Config{
		MaxBatchSize:      params.MaxBatchSize,
		MaxBatchSizeBytes: params.MaxBatchSizeBytes,
		MaxPoolSize:       maxTxPoolSize,
	}
	var pool txpool.TxPool
	switch txPoolImpl {
	case queue.Name:
		pool = queue.New(poolCfg)
	case mapp.Name:
		pool = mapp.New(poolCfg)
	case orderedmap.Name:
		pool = orderedmap.New(poolCfg)
	default:
		return nil, fmt.Errorf("invalid transaction pool: %s", txPoolImpl)
	}

	scheduler := &scheduler{
		maxTxPoolSize: maxTxPoolSize,
		txPool:        pool,
		logger:        logging.GetLogger("runtime/scheduling").With("scheduler", "simple"),
	}

	return scheduler, nil
}
