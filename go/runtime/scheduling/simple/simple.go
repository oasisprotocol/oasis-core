// Package simple implements a simple batching transaction scheduler.
package simple

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
	txpool "github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/priorityqueue"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

const (
	// Name of the scheduler.
	Name = registry.TxnSchedulerSimple
)

type scheduler struct {
	logger *logging.Logger

	txPool        txpool.TxPool
	maxTxPoolSize uint64
}

func (s *scheduler) QueueTx(tx *transaction.CheckedTransaction) error {
	switch err := s.txPool.Add(tx); err {
	case nil:
		return nil
	case txpool.ErrCallAlreadyExists:
		// Return success in case of duplicate calls to avoid the client
		// mistaking this for an actual error.
		s.logger.Warn("ignoring duplicate call",
			"batch", tx,
		)
		return nil
	default:
		return err
	}
}

func (s *scheduler) RemoveTxBatch(tx []hash.Hash) error {
	return s.txPool.RemoveBatch(tx)
}

func (s *scheduler) GetBatch(force bool) []*transaction.CheckedTransaction {
	return s.txPool.GetBatch(force)
}

func (s *scheduler) GetKnownBatch(batch []hash.Hash) ([]*transaction.CheckedTransaction, map[hash.Hash]int) {
	return s.txPool.GetKnownBatch(batch)
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

func (s *scheduler) UpdateParameters(algo string, weightLimits map[transaction.Weight]uint64) error {
	if algo != Name {
		return fmt.Errorf("unexpected transaction scheduling algorithm: %s", algo)
	}

	if err := s.txPool.UpdateConfig(txpool.Config{
		MaxPoolSize:  s.maxTxPoolSize,
		WeightLimits: weightLimits,
	}); err != nil {
		return fmt.Errorf("error updating parameters: %w", err)
	}
	return nil
}

func (s *scheduler) Name() string {
	return Name
}

// New creates a new simple scheduler.
func New(txPoolImpl string, maxTxPoolSize uint64, algo string, weightLimits map[transaction.Weight]uint64) (api.Scheduler, error) {
	if algo != Name {
		return nil, fmt.Errorf("unexpected transaction scheduling algorithm: %s", algo)
	}

	poolCfg := txpool.Config{
		MaxPoolSize:  maxTxPoolSize,
		WeightLimits: weightLimits,
	}
	var pool txpool.TxPool
	switch txPoolImpl {
	case priorityqueue.Name:
		pool = priorityqueue.New(poolCfg)
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
