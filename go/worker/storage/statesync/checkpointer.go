package statesync

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothashApi "github.com/oasisprotocol/oasis-core/go/roothash/api"
	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
)

const (
	// chunkerThreads is target number of subtrees during parallel checkpoint creation.
	// It is intentionally non-configurable since we want operators to produce
	// same checkpoint hashes. The current value was chosen based on the benchmarks
	// done on the modern developer machine.
	chunkerThreads = 12
)

func (w *Worker) newCheckpointer(ctx context.Context, commonNode *committee.Node, localStorage storageApi.LocalBackend) (checkpoint.Checkpointer, error) {
	checkInterval := checkpoint.CheckIntervalDisabled
	if config.GlobalConfig.Storage.Checkpointer.Enabled {
		checkInterval = config.GlobalConfig.Storage.Checkpointer.CheckInterval
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

			blk, rerr := commonNode.Consensus.RootHash().GetGenesisBlock(ctx, &roothashApi.RuntimeRequest{
				RuntimeID: rt.ID,
				Height:    consensus.HeightLatest,
			})
			if rerr != nil {
				return nil, fmt.Errorf("failed to retrieve genesis block: %w", rerr)
			}

			var threads uint16
			if config.GlobalConfig.Storage.Checkpointer.ParallelChunker {
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
		GetRoots: func(ctx context.Context, version uint64) ([]storageApi.Root, error) {
			blk, berr := commonNode.Runtime.History().GetCommittedBlock(ctx, version)
			if berr != nil {
				return nil, berr
			}

			return blk.Header.StorageRoots(), nil
		},
	}

	return checkpoint.NewCheckpointer(
		ctx,
		localStorage.NodeDB(),
		localStorage.Checkpointer(),
		checkpointerCfg,
	)
}

// createCheckpoints is a worker responsible for triggering creation of runtime
// checkpoint everytime a consensus checkpoint is created.
//
// The reason why we do this is to make it faster for storage nodes that use consensus state sync
// to catch up as exactly the right checkpoint will be available.
func (w *Worker) createCheckpoints(ctx context.Context) {
	consensusCp := w.commonNode.Consensus.Checkpointer()
	if consensusCp == nil {
		return
	}

	// Wait for the common node to be initialized.
	select {
	case <-w.commonNode.Initialized():
	case <-ctx.Done():
		return
	}

	// Determine the maximum number of consensus checkpoints to keep.
	consensusParams, err := w.commonNode.Consensus.Core().GetParameters(ctx, consensus.HeightLatest)
	if err != nil {
		w.logger.Error("failed to fetch consensus parameters",
			"err", err,
		)
		return
	}

	ch, sub, err := consensusCp.WatchCheckpoints()
	if err != nil {
		w.logger.Error("failed to watch checkpoints",
			"err", err,
		)
		return
	}
	defer sub.Close()

	var (
		versions []uint64
		blkCh    <-chan *consensus.Block
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
		case <-w.quitCh:
			return
		case <-ctx.Done():
			return
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
				blk, err := w.commonNode.Consensus.RootHash().GetLatestBlock(ctx, &roothashApi.RuntimeRequest{
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
				w.syncedLock.RLock()
				lastSyncedRound := w.syncedState.Round
				w.syncedLock.RUnlock()
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
		}
	}
}
