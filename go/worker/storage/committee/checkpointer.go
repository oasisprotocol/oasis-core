package committee

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/eapache/channels"

	"github.com/oasislabs/oasis-core/go/common/logging"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/runtime/history"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/checkpoint"
)

// CheckpointerConfig is a checkpointer configuration.
type CheckpointerConfig struct {
	CheckInterval time.Duration
}

type checkpointer struct {
	cfg CheckpointerConfig

	creator       checkpoint.Creator
	notifyBlockCh *channels.RingChannel

	logger *logging.Logger
}

func (c *checkpointer) notifyNewBlock(round uint64) {
	c.notifyBlockCh.In() <- round
}

func (c *checkpointer) checkpoint(ctx context.Context, rt *registry.Runtime, round uint64, history history.History) (err error) {
	blk, err := history.GetBlock(ctx, round)
	if err != nil {
		return fmt.Errorf("checkpointer: failed to get block: %w", err)
	}

	roots := blk.Header.StorageRoots()
	defer func() {
		if err == nil {
			return
		}

		// If there is an error, make sure to remove any created checkpoints.
		for _, root := range roots {
			_ = c.creator.DeleteCheckpoint(ctx, &checkpoint.DeleteCheckpointRequest{Version: 1, Root: root})
		}
	}()

	for _, root := range roots {
		c.logger.Info("creating new checkpoint",
			"root", root,
			"chunk_size", rt.Storage.CheckpointChunkSize,
		)

		_, err = c.creator.CreateCheckpoint(ctx, root, rt.Storage.CheckpointChunkSize)
		if err != nil {
			c.logger.Error("failed to create checkpoint",
				"root", root,
				"err", err,
			)
			return fmt.Errorf("checkpointer: failed to create checkpoint: %w", err)
		}
	}
	return nil
}

func (c *checkpointer) maybeCheckpoint(ctx context.Context, rt *registry.Runtime, round uint64, history history.History) error {
	// Get a list of all current checkpoints.
	cps, err := c.creator.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{
		Version:   1,
		Namespace: rt.ID,
	})
	if err != nil {
		return fmt.Errorf("checkpointer: failed to get existing checkpoints: %w", err)
	}

	// Check if we need to create a new checkpoint based on the list of existing checkpoints, the
	// current round and the runtime configuration. Note that for each round we create two
	// checkpoints, one for the state root and another one for the IO root.
	var lastCheckpointRound uint64
	var cpRounds []uint64
	cpsByRound := make(map[uint64][]storage.Root)
	for _, cp := range cps {
		if cpsByRound[cp.Root.Round] == nil {
			cpRounds = append(cpRounds, cp.Root.Round)
		}
		cpsByRound[cp.Root.Round] = append(cpsByRound[cp.Root.Round], cp.Root)
		if len(cpsByRound[cp.Root.Round]) == 2 && cp.Root.Round > lastCheckpointRound {
			lastCheckpointRound = cp.Root.Round
		}
	}
	sort.Slice(cpRounds, func(i, j int) bool { return cpRounds[i] < cpRounds[j] })

	// Checkpoint any missing rounds.
	cpInterval := rt.Storage.CheckpointInterval
	for cpRound := lastCheckpointRound + cpInterval; cpRound < round; cpRound = cpRound + cpInterval {
		c.logger.Info("checkpointing round",
			"round", cpRound,
		)

		if err = c.checkpoint(ctx, rt, cpRound, history); err != nil {
			c.logger.Error("failed to checkpoint round",
				"round", cpRound,
				"err", err,
			)
			return fmt.Errorf("checkpointer: failed to checkpoint round: %w", err)
		}
	}

	// Garbage collect old checkpoints.
	if int(rt.Storage.CheckpointNumKept) < len(cpRounds) {
		c.logger.Info("performing checkpoint garbage collection",
			"num_checkpoints", len(cpRounds),
			"num_kept", rt.Storage.CheckpointNumKept,
		)

		for _, round := range cpRounds[:len(cpRounds)-int(rt.Storage.CheckpointNumKept)] {
			for _, root := range cpsByRound[round] {
				if err = c.creator.DeleteCheckpoint(ctx, &checkpoint.DeleteCheckpointRequest{
					Version: 1,
					Root:    root,
				}); err != nil {
					c.logger.Warn("failed to garbage collect checkpoint",
						"root", root,
						"err", err,
					)
					continue
				}
			}
		}
	}

	return nil
}

func (c *checkpointer) worker(ctx context.Context, runtime runtimeRegistry.Runtime) {
	c.logger.Debug("storage checkpointer started",
		"check_interval", c.cfg.CheckInterval,
	)
	defer func() {
		c.logger.Debug("storage checkpointer terminating")
	}()

	// Use a ticker to avoid checking for checkpoints too often.
	ticker := time.NewTicker(c.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var round uint64
			select {
			case <-ctx.Done():
				return
			case r := <-c.notifyBlockCh.Out():
				round = r.(uint64)
			}

			rt, err := runtime.RegistryDescriptor(ctx)
			if err != nil {
				c.logger.Warn("failed to get runtime descriptor",
					"round", round,
					"err", err,
				)
				continue
			}

			// Don't checkpoint if checkpoints are disabled.
			if rt.Storage.CheckpointInterval == 0 {
				continue
			}

			if err := c.maybeCheckpoint(ctx, rt, round, runtime.History()); err != nil {
				c.logger.Error("failed to checkpoint",
					"round", round,
					"err", err,
				)
				continue
			}
		}
	}
}

func newCheckpointer(
	ctx context.Context,
	runtime runtimeRegistry.Runtime,
	creator checkpoint.Creator,
	cfg CheckpointerConfig,
) (*checkpointer, error) {
	c := &checkpointer{
		cfg:           cfg,
		creator:       creator,
		notifyBlockCh: channels.NewRingChannel(1),
		logger:        logging.GetLogger("worker/storage/committee/checkpointer").With("runtime_id", runtime.ID()),
	}
	go c.worker(ctx, runtime)
	return c, nil
}
