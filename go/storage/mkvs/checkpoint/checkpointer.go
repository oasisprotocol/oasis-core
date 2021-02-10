package checkpoint

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

// CheckpointerConfig is a checkpointer configuration.
type CheckpointerConfig struct {
	// Name identifying this checkpointer in logs.
	Name string

	// Namespace is the storage namespace this checkpointer is for.
	Namespace common.Namespace

	// CheckInterval is the interval on which to check if any checkpointing is needed.
	CheckInterval time.Duration

	// RootsPerVersion is the number of roots per version.
	RootsPerVersion int

	// Parameters are the checkpoint creation parameters.
	Parameters *CreationParameters
	// GetParameters can be used instead of specifying Parameters to dynamically fetch the current
	// checkpoint parameters. In this case Parameters must be set to nil.
	GetParameters func(context.Context) (*CreationParameters, error)

	// GetRoots can be used to override which finalized roots should be checkpointed. If this is not
	// specified, all finalized roots will be checkpointed.
	//
	// This must return exactly RootsPerVersion roots.
	GetRoots func(context.Context, uint64) ([]node.Root, error)
}

// CreationParameters are the checkpoint creation parameters used by the checkpointer.
type CreationParameters struct {
	// Interval is the expected runtime state checkpoint interval (in rounds).
	Interval uint64

	// NumKept is the expected minimum number of checkpoints to keep.
	NumKept uint64

	// ChunkSize is the chunk size parameter for checkpoint creation.
	ChunkSize uint64

	// InitialVersion is the initial version.
	InitialVersion uint64
}

// Checkpointer is a checkpointer.
type Checkpointer interface {
	// NotifyNewVersion notifies the checkpointer that a new version has been finalized.
	NotifyNewVersion(version uint64)

	// Flush makes the checkpointer immediately process any notifications.
	Flush()
}

type checkpointer struct {
	cfg CheckpointerConfig

	ndb      db.NodeDB
	creator  Creator
	notifyCh *channels.RingChannel
	flushCh  *channels.RingChannel
	statusCh chan struct{}

	logger *logging.Logger
}

// Implements Checkpointer.
func (c *checkpointer) NotifyNewVersion(version uint64) {
	c.notifyCh.In() <- version
}

// Implements Checkpointer.
func (c *checkpointer) Flush() {
	c.flushCh.In() <- struct{}{}
}

func (c *checkpointer) checkpoint(ctx context.Context, version uint64, params *CreationParameters) (err error) {
	var roots []node.Root
	if c.cfg.GetRoots == nil {
		roots, err = c.ndb.GetRootsForVersion(ctx, version)
	} else {
		roots, err = c.cfg.GetRoots(ctx, version)
	}
	if err != nil {
		return fmt.Errorf("checkpointer: failed to get storage roots: %w", err)
	}
	if len(roots) != c.cfg.RootsPerVersion {
		return fmt.Errorf("checkpointer: unexpected number of roots for version (expected: %d got: %d)",
			c.cfg.RootsPerVersion,
			len(roots),
		)
	}

	defer func() {
		if err == nil {
			return
		}

		// If there is an error, make sure to remove any created checkpoints.
		for _, root := range roots {
			_ = c.creator.DeleteCheckpoint(ctx, checkpointVersion, root)
		}
	}()

	for _, root := range roots {
		c.logger.Info("creating new checkpoint",
			"root", root,
			"chunk_size", params.ChunkSize,
		)

		_, err = c.creator.CreateCheckpoint(ctx, root, params.ChunkSize)
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

func (c *checkpointer) maybeCheckpoint(ctx context.Context, version uint64, params *CreationParameters) error {
	// Get a list of all current checkpoints.
	cps, err := c.creator.GetCheckpoints(ctx, &GetCheckpointsRequest{
		Version:   checkpointVersion,
		Namespace: c.cfg.Namespace,
	})
	if err != nil {
		return fmt.Errorf("checkpointer: failed to get existing checkpoints: %w", err)
	}

	// Check if we need to create a new checkpoint based on the list of existing checkpoints.
	var lastCheckpointVersion uint64
	var cpVersions []uint64
	cpsByVersion := make(map[uint64][]node.Root)
	for _, cp := range cps {
		if cpsByVersion[cp.Root.Version] == nil {
			cpVersions = append(cpVersions, cp.Root.Version)
		}
		cpsByVersion[cp.Root.Version] = append(cpsByVersion[cp.Root.Version], cp.Root)
		if len(cpsByVersion[cp.Root.Version]) == c.cfg.RootsPerVersion && cp.Root.Version > lastCheckpointVersion {
			lastCheckpointVersion = cp.Root.Version
		}
	}
	sort.Slice(cpVersions, func(i, j int) bool { return cpVersions[i] < cpVersions[j] })

	// Make sure to not start earlier than the earliest version.
	earlyVersion, err := c.ndb.GetEarliestVersion(ctx)
	if err != nil {
		return fmt.Errorf("checkpointer: failed to get earliest version: %w", err)
	}
	if lastCheckpointVersion < earlyVersion {
		lastCheckpointVersion = earlyVersion - params.Interval
	}
	if lastCheckpointVersion < params.InitialVersion {
		lastCheckpointVersion = params.InitialVersion - params.Interval
	}

	// Checkpoint any missing versions.
	for cpVersion := lastCheckpointVersion + params.Interval; cpVersion < version; cpVersion = cpVersion + params.Interval {
		c.logger.Info("checkpointing version",
			"version", cpVersion,
		)

		if err = c.checkpoint(ctx, cpVersion, params); err != nil {
			c.logger.Error("failed to checkpoint version",
				"version", cpVersion,
				"err", err,
			)
			return fmt.Errorf("checkpointer: failed to checkpoint version: %w", err)
		}
	}

	// Garbage collect old checkpoints.
	if int(params.NumKept) < len(cpVersions) {
		c.logger.Info("performing checkpoint garbage collection",
			"num_checkpoints", len(cpVersions),
			"num_kept", params.NumKept,
		)

		for _, version := range cpVersions[:len(cpVersions)-int(params.NumKept)] {
			for _, root := range cpsByVersion[version] {
				if err = c.creator.DeleteCheckpoint(ctx, checkpointVersion, root); err != nil {
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

func (c *checkpointer) worker(ctx context.Context) {
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
		case <-c.flushCh.Out():
		}

		var version uint64
		select {
		case <-ctx.Done():
			return
		case v := <-c.notifyCh.Out():
			version = v.(uint64)
		}

		// Fetch current checkpoint parameters.
		params := c.cfg.Parameters
		if params == nil && c.cfg.GetParameters != nil {
			var err error
			params, err = c.cfg.GetParameters(ctx)
			if err != nil {
				c.logger.Error("failed to get checkpoint parameters",
					"err", err,
					"version", version,
				)
				continue
			}
		}
		if params == nil {
			c.logger.Error("no checkpoint parameters")
			continue
		}

		// Don't checkpoint if checkpoints are disabled.
		if params.Interval == 0 {
			continue
		}

		if err := c.maybeCheckpoint(ctx, version, params); err != nil {
			c.logger.Error("failed to checkpoint",
				"version", version,
				"err", err,
			)
			continue
		}

		// Emit status update if someone is listening. This is only used in tests.
		select {
		case c.statusCh <- struct{}{}:
		default:
		}
	}
}

// NewCheckpointer creates a new checkpointer that can be notified of new finalized versions and
// will automatically generate the configured number of checkpoints.
func NewCheckpointer(
	ctx context.Context,
	ndb db.NodeDB,
	creator Creator,
	cfg CheckpointerConfig,
) (Checkpointer, error) {
	c := &checkpointer{
		cfg:      cfg,
		ndb:      ndb,
		creator:  creator,
		notifyCh: channels.NewRingChannel(1),
		flushCh:  channels.NewRingChannel(1),
		statusCh: make(chan struct{}),
		logger:   logging.GetLogger("storage/mkvs/checkpoint/"+cfg.Name).With("namespace", cfg.Namespace),
	}
	go c.worker(ctx)
	return c, nil
}
