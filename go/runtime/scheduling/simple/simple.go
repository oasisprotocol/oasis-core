// Package simple implements a simple batching transaction scheduler.
package simple

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
)

const (
	// Name of the scheduler.
	Name = registry.TxnSchedulerSimple
)

type scheduler struct {
	cfg           config
	incomingQueue *incomingQueue

	dispatcher api.TransactionDispatcher

	logger *logging.Logger
}

type config struct {
	maxQueueSize      uint64
	maxBatchSize      uint64
	maxBatchSizeBytes uint64
}

func (s *scheduler) scheduleBatch(force bool) error {
	batch, err := s.incomingQueue.Take(force)
	if err != nil && err != errNoBatchAvailable {
		s.logger.Error("failed to get batch from the queue",
			"err", err,
		)
		return err
	}

	if len(batch) > 0 {
		// Try to dispatch batch.
		if err := s.dispatcher.Dispatch(batch); err != nil {
			// Put the batch back into the incoming queue in case this failed.
			if errAB := s.incomingQueue.AddBatch(batch); errAB != nil {
				s.logger.Warn("failed to add batch back into the incoming queue",
					"err", errAB,
				)
			}
			return err
		}
	}

	return nil
}

func (s *scheduler) ScheduleTx(tx []byte) error {
	if err := s.incomingQueue.Add(tx); err != nil {
		// Return success in case of duplicate calls to avoid the client
		// mistaking this for an actual error.
		if err == errCallAlreadyExists {
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
	return s.incomingQueue.AddBatch(batch)
}

func (s *scheduler) RemoveTxBatch(tx [][]byte) error {
	return s.incomingQueue.RemoveBatch(tx)
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

func (s *scheduler) UnscheduledSize() int {
	return s.incomingQueue.Size()
}

func (s *scheduler) IsQueued(id hash.Hash) bool {
	return s.incomingQueue.IsQueued(id)
}

func (s *scheduler) Clear() {
	s.incomingQueue.Clear()
}

func (s *scheduler) Initialize(td api.TransactionDispatcher) error {
	s.dispatcher = td

	return nil
}

func (s *scheduler) IsInitialized() bool {
	return s.dispatcher != nil
}

// New creates a new simple scheduler.
func New(maxQueueSize, maxBatchSize, maxBatchSizeBytes uint64) (api.Scheduler, error) {
	cfg := config{
		maxQueueSize:      maxQueueSize,
		maxBatchSize:      maxBatchSize,
		maxBatchSizeBytes: maxBatchSizeBytes,
	}
	scheduler := &scheduler{
		cfg:           cfg,
		incomingQueue: newIncomingQueue(cfg.maxQueueSize, cfg.maxBatchSize, cfg.maxBatchSizeBytes),
		logger:        logging.GetLogger("runtime/scheduling").With("scheduler", "simple"),
	}

	return scheduler, nil
}
