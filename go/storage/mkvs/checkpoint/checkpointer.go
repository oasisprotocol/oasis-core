package checkpoint

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/random"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

// Specifies the factor by which the checkpoint interval (in wall clock time)
// is randomized.
const checkpointIntervalRandomizationFactor = 0.1

// CheckIntervalDisabled is the checkpointing interval which basically disables periodic
// checkpoints (unless a checkpoint is forced).
const CheckIntervalDisabled time.Duration = 1<<63 - 1

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

	// ForceCheckpoint makes the checkpointer create a checkpoint of the given version even if it is
	// outside the regular checkpoint schedule. In case the checkpoint at that version already
	// exists, this will be a no-op.
	//
	// The checkpoint will be created asynchronously.
	ForceCheckpoint(version uint64)

	// WatchCheckpoints returns a channel that produces a stream of checkpointed versions. The
	// versions are emitted before the checkpointing process starts.
	WatchCheckpoints() (<-chan uint64, pubsub.ClosableSubscription, error)

	// Flush makes the checkpointer immediately process any notifications.
	Flush()

	// Pause pauses or unpauses the checkpointer. Pausing doesn't influence the checkpointing
	// intervals; after unpausing, a checkpoint won't be created immediately, but the checkpointer
	// will wait for the next regular event.
	Pause(pause bool)
}

type checkpointer struct {
	cfg CheckpointerConfig

	ndb        db.NodeDB
	creator    Creator
	notifyCh   *channels.RingChannel
	forceCh    *channels.RingChannel
	flushCh    *channels.RingChannel
	statusCh   chan struct{}
	pausedCh   chan bool
	cpNotifier *pubsub.Broker

	logger *logging.Logger
}

// Implements Checkpointer.
func (c *checkpointer) NotifyNewVersion(version uint64) {
	c.notifyCh.In() <- version
}

// Implements Checkpointer.
func (c *checkpointer) ForceCheckpoint(version uint64) {
	c.forceCh.In() <- version
}

// Implements Checkpointer.
func (c *checkpointer) WatchCheckpoints() (<-chan uint64, pubsub.ClosableSubscription, error) {
	ch := make(chan uint64)
	sub := c.cpNotifier.Subscribe()
	sub.Unwrap(ch)

	return ch, sub, nil
}

// Implements Checkpointer.
func (c *checkpointer) Flush() {
	c.flushCh.In() <- struct{}{}
}

func (c *checkpointer) Pause(pause bool) {
	c.pausedCh <- pause
}

func (c *checkpointer) checkpoint(ctx context.Context, version uint64, params *CreationParameters) (err error) {
	// Notify watchers about the checkpoint we are about to make.
	c.cpNotifier.Broadcast(version)

	var roots []node.Root
	if c.cfg.GetRoots == nil {
		roots, err = c.ndb.GetRootsForVersion(version)
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
			_ = c.creator.DeleteCheckpoint(ctx, checkpointV1, root)
		}
	}()

	c.logger.Debug("found roots to create for checkpoint",
		"version", version,
		"num_roots", len(roots),
	)

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
		Version:   checkpointV1,
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
	earlyVersion := c.ndb.GetEarliestVersion()
	firstCheckpointVersion := lastCheckpointVersion + 1 // We can checkpoint the next version.
	if firstCheckpointVersion < earlyVersion {
		firstCheckpointVersion = earlyVersion
	}
	if firstCheckpointVersion < params.InitialVersion {
		firstCheckpointVersion = params.InitialVersion
	}

	// Checkpoint any missing versions in descending order, stopping at NumKept checkpoints.
	newCheckpointVersion := ((version-params.InitialVersion)/params.Interval)*params.Interval + params.InitialVersion
	var numAddedCheckpoints uint64
	for cpVersion := newCheckpointVersion; cpVersion >= firstCheckpointVersion; {
		c.logger.Info("checkpointing version",
			"version", cpVersion,
		)

		if err = c.checkpoint(ctx, cpVersion, params); err != nil {
			c.logger.Error("failed to checkpoint version",
				"version", cpVersion,
				"err", err,
			)
			break
		}

		// Move to the next version, avoiding possible underflow.
		if cpVersion < params.Interval {
			break
		}
		cpVersion = cpVersion - params.Interval

		// Stop when we have enough checkpoints as otherwise we will be creating checkpoints which
		// will be garbage collected anyway.
		numAddedCheckpoints++
		if numAddedCheckpoints >= params.NumKept {
			break
		}
	}

	// Garbage collect old checkpoints, first making sure that genesis checkpoint is excluded.
	if len(cpVersions) > 0 && cpVersions[0] == params.InitialVersion {
		cpVersions = cpVersions[1:]
	}
	if int(params.NumKept) < len(cpVersions) {
		c.logger.Info("performing checkpoint garbage collection",
			"num_checkpoints", len(cpVersions),
			"num_kept", params.NumKept,
		)

		for _, version := range cpVersions[:len(cpVersions)-int(params.NumKept)] {
			for _, root := range cpsByVersion[version] {
				if err = c.creator.DeleteCheckpoint(ctx, checkpointV1, root); err != nil {
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

	paused := false

	for {
		var interval time.Duration
		switch c.cfg.CheckInterval {
		case CheckIntervalDisabled:
			interval = CheckIntervalDisabled
		default:
			interval = random.GetRandomValueFromInterval(
				checkpointIntervalRandomizationFactor,
				rand.Float64(),
				c.cfg.CheckInterval,
			)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		case <-c.flushCh.Out():
		case paused = <-c.pausedCh:
			continue
		}

		var (
			version uint64
			force   bool
		)
		select {
		case <-ctx.Done():
			return
		case v := <-c.notifyCh.Out():
			version = v.(uint64)
		case v := <-c.forceCh.Out():
			version = v.(uint64)
			force = true
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
		switch {
		case force:
			// Always checkpoint when forced.
		case paused:
			continue
		case params.Interval == 0:
			continue
		case c.cfg.CheckInterval == CheckIntervalDisabled:
			continue
		default:
		}

		var err error
		switch force {
		case false:
			err = c.maybeCheckpoint(ctx, version, params)
		case true:
			err = c.checkpoint(ctx, version, params)
		}
		if err != nil {
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
		cfg:        cfg,
		ndb:        ndb,
		creator:    creator,
		notifyCh:   channels.NewRingChannel(1),
		forceCh:    channels.NewRingChannel(1),
		flushCh:    channels.NewRingChannel(1),
		statusCh:   make(chan struct{}),
		pausedCh:   make(chan bool),
		cpNotifier: pubsub.NewBroker(false),
		logger:     logging.GetLogger("storage/mkvs/checkpoint/"+cfg.Name).With("namespace", cfg.Namespace),
	}
	go c.worker(ctx)
	return c, nil
}
