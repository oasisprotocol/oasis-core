// Package batching implements a batching transaction scheduling algorithm.
package batching

import (
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/worker/common/committee"
	"github.com/oasislabs/ekiden/go/worker/txnscheduler/algorithm/api"
)

const (
	// Name of the scheduling algorithm.
	Name = "batching"

	cfgMaxQueueSize      = "worker.txnscheduler.batching.max_queue_size"
	cfgMaxBatchSize      = "worker.txnscheduler.batching.max_batch_size"
	cfgMaxBatchSizeBytes = "worker.txnscheduler.batching.max_batch_size_bytes"
)

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
	// Guarding against EpochTransition() modifying current epoch.
	s.RLock()
	defer s.RUnlock()

	batch, err := s.incomingQueue.Take(force)
	if err != nil && err != errNoBatchAvailable {
		s.logger.Error("failed to get batch from the queue",
			"err", err,
		)
		return err
	}

	// We cannot schedule anything until there is an epoch transition.
	if s.epoch == nil {
		s.logger.Warn("not scheduling before epoch transition")
		return nil
	}

	if len(batch) > 0 {
		// The simple batching algorithm only supports a single compute committee. Use
		// with multiple committees will currently cause the rounds to fail as all other
		// committees will be idle.
		var committeeID hash.Hash
		for id := range s.epoch.GetComputeCommittees() {
			committeeID = id
			break
		}

		if err := s.dispatcher.Dispatch(committeeID, batch); err != nil {
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

// New creates a new batching algorithm.
func New() (api.Algorithm, error) {
	cfg := config{
		maxQueueSize:      uint64(viper.GetInt(cfgMaxQueueSize)),
		maxBatchSize:      uint64(viper.GetInt(cfgMaxBatchSize)),
		maxBatchSizeBytes: uint64(viper.GetSizeInBytes(cfgMaxBatchSizeBytes)),
	}
	batching := batchingState{
		cfg:           cfg,
		incomingQueue: newIncomingQueue(cfg.maxQueueSize, cfg.maxBatchSize, cfg.maxBatchSizeBytes),
		logger:        logging.GetLogger("txscheduler/algo/batching"),
	}

	return &batching, nil
}

// RegisterFlags registers the configuration flag for the batching algorithm.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Uint64(cfgMaxQueueSize, 10000, "Maximum size of the batching queue")
		cmd.Flags().Uint64(cfgMaxBatchSize, 1000, "Maximum size of a batch of runtime requests")
		cmd.Flags().String(cfgMaxBatchSizeBytes, "16mb", "Maximum size (in bytes) of a batch of runtime requests")
	}

	for _, v := range []string{
		cfgMaxQueueSize,
		cfgMaxBatchSize,
		cfgMaxBatchSizeBytes,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
