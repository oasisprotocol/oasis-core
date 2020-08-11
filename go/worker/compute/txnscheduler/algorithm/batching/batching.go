// Package batching implements a batching transaction scheduling algorithm.
package batching

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/worker/compute/txnscheduler/algorithm/api"
)

const (
	// Name of the scheduling algorithm.
	Name = registry.TxnSchedulerAlgorithmBatching

	cfgMaxQueueSize = "worker.txnscheduler.batching.max_queue_size"
)

// Flags has the configuration flag for the batching algorithm.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

type batchingState struct {
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

func (s *batchingState) scheduleBatch(force bool) error {
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
				s.logger.Error("failed to add batch back into the incoming queue",
					"err", errAB,
				)
			}
			return err
		}
	}

	return nil
}

func (s *batchingState) ScheduleTx(tx []byte) error {
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
		s.logger.Error("failed scheduling a batch",
			"error", err,
		)
	}

	return nil
}

func (s *batchingState) Flush() error {
	// Force schedule a batch.
	if err := s.scheduleBatch(true); err != nil {
		s.logger.Error("failed scheduling a batch",
			"error", err,
		)
		return err
	}

	return nil
}

func (s *batchingState) UnscheduledSize() int {
	return s.incomingQueue.Size()
}

func (s *batchingState) IsQueued(id hash.Hash) bool {
	return s.incomingQueue.IsQueued(id)
}

func (s *batchingState) Clear() {
	s.incomingQueue.Clear()
}

func (s *batchingState) Initialize(td api.TransactionDispatcher) error {
	s.dispatcher = td

	return nil
}

func (s *batchingState) IsInitialized() bool {
	return s.dispatcher != nil
}

// New creates a new batching algorithm.
func New(maxBatchSize, maxBatchSizeBytes uint64) (api.Algorithm, error) {
	cfg := config{
		maxQueueSize:      uint64(viper.GetInt(cfgMaxQueueSize)),
		maxBatchSize:      maxBatchSize,
		maxBatchSizeBytes: maxBatchSizeBytes,
	}
	batching := batchingState{
		cfg:           cfg,
		incomingQueue: newIncomingQueue(cfg.maxQueueSize, cfg.maxBatchSize, cfg.maxBatchSizeBytes),
		logger:        logging.GetLogger("txn_scheduler/algo/batching"),
	}

	return &batching, nil
}

func init() {
	Flags.Uint64(cfgMaxQueueSize, 10000, "Maximum size of the batching queue")

	_ = viper.BindPFlags(Flags)
}
