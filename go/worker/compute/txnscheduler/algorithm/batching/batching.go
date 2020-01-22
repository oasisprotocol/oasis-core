// Package batching implements a batching transaction scheduling algorithm.
package batching

import (
	"sync"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/logging"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/worker/common/committee"
	"github.com/oasislabs/oasis-core/go/worker/compute/txnscheduler/algorithm/api"
)

const (
	// Name of the scheduling algorithm.
	Name = registry.TxnSchedulerAlgorithmBatching

	cfgMaxQueueSize = "worker.txnscheduler.batching.max_queue_size"
)

// Flags has the configuration flag for the batching algorithm.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

type batchingState struct {
	sync.RWMutex

	cfg           config
	incomingQueue *incomingQueue

	dispatcher api.TransactionDispatcher

	epoch *committee.EpochSnapshot

	logger *logging.Logger
}

type config struct {
	maxQueueSize      uint64
	maxBatchSize      uint64
	maxBatchSizeBytes uint64
}

func (s *batchingState) scheduleBatch(force bool) error {
	// The simple batching algorithm only supports a single executor committee. Use
	// with multiple committees will currently cause the rounds to fail as all other
	// committees will be idle.
	var committeeID *hash.Hash
	func() {
		// Guarding against EpochTransition() modifying current epoch.
		s.RLock()
		defer s.RUnlock()

		// We cannot schedule anything until there is an epoch transition.
		if s.epoch == nil {
			return
		}

		for id := range s.epoch.GetExecutorCommittees() {
			committeeID = &id
			break
		}
	}()
	if committeeID == nil {
		return nil
	}

	batch, err := s.incomingQueue.Take(force)
	if err != nil && err != errNoBatchAvailable {
		s.logger.Error("failed to get batch from the queue",
			"err", err,
		)
		return err
	}

	if len(batch) > 0 {
		// Try to dispatch batch to the first committee.
		if err := s.dispatcher.Dispatch(*committeeID, batch); err != nil {
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

func (s *batchingState) EpochTransition(epoch *committee.EpochSnapshot) error {
	s.Lock()
	defer s.Unlock()

	s.epoch = epoch
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
