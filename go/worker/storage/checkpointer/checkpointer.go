// Package checkpointer defines logic for periodically creating checkpoints
// of the runtime state.
package checkpointer

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	commonFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	roothashAPI "github.com/oasisprotocol/oasis-core/go/roothash/api"
	storageAPI "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/statesync"
)

// chunkerThreads is target number of subtrees during parallel checkpoint creation.
// It is intentionally non-configurable since we want operators to produce
// same checkpoint hashes. The current value was chosen based on the benchmarks
// done on the modern developer machine.
const chunkerThreads = 12

// Worker is responsible for creating runtime checkpoints for every consensus checkpoint,
// and notifying the checkpointer about the new finalized versions.
//
// If the checkpointer is disabled, it will wait until the state is initialized
// and ensure at least checkpoint for the genesis height was created.
type Worker struct {
	commonNode   *committee.Node
	localStorage storageAPI.LocalBackend
	checkpointer checkpoint.Checkpointer
	stateSync    *statesync.Worker
	cfg          Config
	logger       *logging.Logger
}

// Config is the worker configuration.
type Config struct {
	// CheckpointerEnabled specifies creation of period runtime checkpoints is enabled.
	CheckpointerEnabled bool
	// CheckInterval is the interval on which to check if any checkpointing is needed.
	CheckInterval time.Duration
	// ParallelChunker specifies if the new parallel chunking algorithm can be used.
	ParallelChunker bool
}

// New creates new worker.
func New(commonNode *committee.Node, localStorage storageAPI.LocalBackend, stateSync *statesync.Worker, cfg Config) (*Worker, error) {
	checkInterval := checkpoint.CheckIntervalDisabled
	if cfg.CheckpointerEnabled {
		checkInterval = cfg.CheckInterval
	}
	checkpointerCfg := checkpoint.CheckpointerConfig{
		Name:            "runtime",
		Namespace:       commonNode.Runtime.ID(),
		CheckInterval:   checkInterval,
		RootsPerVersion: 2, // State root and I/O root.
		GetParameters: func(ctx context.Context) (*checkpoint.CreationParameters, error) {
			rt, rerr := commonNode.Runtime.ActiveDescriptor(ctx)
			if rerr != nil {
				return nil, fmt.Errorf("failed to retrieve runtime descriptor: %w", rerr)
			}

			blk, rerr := commonNode.Consensus.RootHash().GetGenesisBlock(ctx, &roothashAPI.RuntimeRequest{
				RuntimeID: rt.ID,
				Height:    consensusAPI.HeightLatest,
			})
			if rerr != nil {
				return nil, fmt.Errorf("failed to retrieve genesis block: %w", rerr)
			}

			var threads uint16
			if cfg.ParallelChunker {
				threads = chunkerThreads
			}

			return &checkpoint.CreationParameters{
				Interval:       rt.Storage.CheckpointInterval,
				NumKept:        rt.Storage.CheckpointNumKept,
				ChunkSize:      rt.Storage.CheckpointChunkSize,
				InitialVersion: blk.Header.Round,
				ChunkerThreads: threads,
			}, nil
		},
		GetRoots: func(ctx context.Context, version uint64) ([]storageAPI.Root, error) {
			blk, berr := commonNode.Runtime.History().GetCommittedBlock(ctx, version)
			if berr != nil {
				return nil, berr
			}

			return blk.Header.StorageRoots(), nil
		},
	}

	checkpointer := checkpoint.NewCheckpointer(
		localStorage.NodeDB(),
		localStorage.Checkpointer(),
		checkpointerCfg,
	)

	return &Worker{
		commonNode:   commonNode,
		localStorage: localStorage,
		checkpointer: checkpointer,
		stateSync:    stateSync,
		cfg:          cfg,
		logger:       logging.GetLogger("worker/storage/checkpointer").With("runtime_id", commonNode.Runtime.ID()),
	}, nil
}

func (w *Worker) PauseCheckpointer(pause bool) error {
	if !commonFlags.DebugDontBlameOasis() {
		return api.ErrCantPauseCheckpointer
	}
	w.checkpointer.Pause(pause)
	return nil
}

// Serve runs the worker.
func (w *Worker) Serve(ctx context.Context) error {
	w.logger.Info("started")
	defer w.logger.Info("stopped")

	consensusCp := w.commonNode.Consensus.Checkpointer()
	if consensusCp == nil {
		return nil // TODO was existing code robust here?
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() { // TODO make it more robust as worker should probably stop here?
		if err := w.checkpointer.Serve(ctx); err != nil {
			w.logger.Error("checkpointer failed", "err", err)
		}
	}()

	if err := w.ensureGenesisCheckpoint(ctx); err != nil {
		return fmt.Errorf("failed to ensure genesis checkpoint was created: %w", err)
	}

	if !w.cfg.CheckpointerEnabled {
		return nil // We can return safely after creating the genesis checkpoint.
	}

	// Determine the maximum number of consensus checkpoints to keep.
	// TODO: This should probably be checked more then once, as params can change without the node
	//       being restarted.
	consensusParams, err := w.commonNode.Consensus.Core().GetParameters(ctx, consensusAPI.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}

	ch, sub, err := consensusCp.WatchCheckpoints()
	if err != nil {
		return fmt.Errorf("failed to watch checkpoints: %w", err)
	}
	defer sub.Close()

	finalizeCh, sub, err := w.stateSync.WatchFinalizedRounds()
	if err != nil {
		return fmt.Errorf("failed to watch finalized summaries: %w", err)
	}
	defer sub.Close()

	var (
		versions []uint64
		blkCh    <-chan *consensusAPI.Block
		blkSub   pubsub.ClosableSubscription
	)
	defer func() {
		if blkCh != nil {
			blkSub.Close()
			blkSub = nil
			blkCh = nil
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case version := <-ch:
			// We need to wait for the next version as that is what will be in the consensus
			// checkpoint.
			versions = append(versions, version+1)
			// Make sure that we limit the size of the checkpoint queue.
			if uint64(len(versions)) > consensusParams.Parameters.StateCheckpointNumKept {
				versions = versions[1:]
			}

			w.logger.Debug("consensus checkpoint detected, queuing runtime checkpoint",
				"version", version+1,
				"num_versions", len(versions),
			)

			if blkCh == nil {
				blkCh, blkSub, err = w.commonNode.Consensus.Core().WatchBlocks(ctx)
				if err != nil {
					w.logger.Error("failed to watch blocks",
						"err", err,
					)
					continue
				}
			}
		case blk := <-blkCh:
			// If there's nothing remaining, unsubscribe.
			if len(versions) == 0 {
				w.logger.Debug("no more queued consensus checkpoint versions")

				blkSub.Close()
				blkSub = nil
				blkCh = nil
				continue
			}

			var newVersions []uint64
			for idx, version := range versions {
				if version > uint64(blk.Height) {
					// We need to wait for further versions.
					newVersions = versions[idx:]
					break
				}

				// Lookup what runtime round corresponds to the given consensus layer version and make
				// sure we checkpoint it.
				blk, err := w.commonNode.Consensus.RootHash().GetLatestBlock(ctx, &roothashAPI.RuntimeRequest{
					RuntimeID: w.commonNode.Runtime.ID(),
					Height:    int64(version),
				})
				if err != nil {
					w.logger.Error("failed to get runtime block corresponding to consensus checkpoint",
						"err", err,
						"height", version,
					)
					continue
				}

				// We may have not yet synced the corresponding runtime round locally. In this case
				// we need to wait until this is the case.
				lastSyncedRound, _, _ := w.stateSync.GetLastSynced()
				if blk.Header.Round > lastSyncedRound {
					w.logger.Debug("runtime round not available yet for checkpoint, waiting",
						"height", version,
						"round", blk.Header.Round,
						"last_synced_round", lastSyncedRound,
					)
					newVersions = versions[idx:]
					break
				}

				// Force runtime storage checkpointer to create a checkpoint at this round.
				w.logger.Info("consensus checkpoint, force runtime checkpoint",
					"height", version,
					"round", blk.Header.Round,
				)

				w.checkpointer.ForceCheckpoint(blk.Header.Round)
			}
			versions = newVersions
		case round := <-finalizeCh:
			w.checkpointer.NotifyNewVersion(round)
		}
	}
}

func (w *Worker) ensureGenesisCheckpoint(ctx context.Context) error {
	// Wait for the common node to be initialized.
	select {
	case <-w.commonNode.Initialized():
	case <-ctx.Done():
		return ctx.Err()
	}

	// Wait for state sync worker to be initialized which guarantees us to have the state initialized.
	select {
	case <-w.stateSync.Initialized():
	case <-ctx.Done():
		return ctx.Err()
	}

	genesisBlock, err := w.commonNode.Consensus.RootHash().GetGenesisBlock(ctx, &roothashAPI.RuntimeRequest{
		RuntimeID: w.commonNode.Runtime.ID(),
		Height:    consensusAPI.HeightLatest,
	})
	if err != nil {
		return fmt.Errorf("can't retrieve genesis block: %w", err)
	}

	ch, sub, err := w.checkpointer.WatchCreatedCheckpoints()
	if err != nil {
		return fmt.Errorf("failed to watch created checkpoints: %w", err)
	}
	defer sub.Close()

	_, err = w.localStorage.Checkpointer().GetCheckpoint(ctx, 1, genesisBlock.Header.StorageRootState())
	if err == nil { // if NOT error we already have a checkpoint. TODO: this is not robust, even though genesis has no io root.
		return nil
	}

	// Notify the checkpointer of the genesis round so it can be checkpointed.
	if w.checkpointer != nil {
		w.checkpointer.ForceCheckpoint(genesisBlock.Header.Round)
		w.checkpointer.Flush()
	}

	// TODO add timeout.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case r := <-ch:
			if r != genesisBlock.Header.Round {
				continue
			}
			return nil // genesis checkpoint created successfully.
		}
	}
}
