// Package upgrade implements the node upgrade backend.
//
// After submitting an upgrade descriptor, the old node may continue
// running or be restarted up to the point when the consensus layer reaches
// the upgrade epoch. The new node may not be started until the old node has
// reached the upgrade epoch.
package upgrade

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade/migrations"
)

var (
	_ api.Backend = (*upgradeManager)(nil)

	metadataStoreKey = []byte("descriptors")

	thisVersion = makeVersionString()
)

func makeVersionString() string {
	return version.SoftwareVersion
}

type upgradeManager struct {
	store   *persistent.ServiceStore
	pending []*api.PendingUpgrade
	lock    sync.Mutex

	dataDir string

	logger *logging.Logger
}

func (u *upgradeManager) SubmitDescriptor(ctx context.Context, descriptor *api.Descriptor) error {
	u.lock.Lock()
	defer u.lock.Unlock()

	for _, pu := range u.pending {
		if pu.Descriptor == descriptor {
			return api.ErrAlreadyPending
		}
	}

	pending := &api.PendingUpgrade{
		Descriptor: descriptor,
	}
	pending.SubmittingVersion = thisVersion
	u.pending = append(u.pending, pending)

	u.logger.Info("received upgrade descriptor, scheduling shutdown",
		"name", pending.Descriptor.Name,
		"epoch", pending.Descriptor.Epoch,
	)

	return u.flushDescriptorLocked()
}

func (u *upgradeManager) PendingUpgrades(ctx context.Context) ([]*api.PendingUpgrade, error) {
	u.lock.Lock()
	defer u.lock.Unlock()

	return u.pending, nil
}

func (u *upgradeManager) CancelUpgrade(ctx context.Context, name string) error {
	u.lock.Lock()
	defer u.lock.Unlock()

	if len(u.pending) == 0 {
		// Make sure nothing is saved.
		return u.flushDescriptorLocked()
	}

	var pending []*api.PendingUpgrade
	for _, pu := range u.pending {
		if pu.Descriptor.Name != name {
			pending = append(pending, pu)
			continue
		}
		if pu.RunningVersion != "" || pu.UpgradeHeight != api.InvalidUpgradeHeight || pu.HasAnyStages() {
			return api.ErrUpgradeInProgress
		}
	}
	oldPending := u.pending
	u.pending = pending
	if err := u.flushDescriptorLocked(); err != nil {
		u.pending = oldPending
		return err
	}
	return nil
}

func (u *upgradeManager) checkStatus() error {
	var err error

	if err = u.store.GetCBOR(metadataStoreKey, &u.pending); err != nil {
		u.pending = nil
		if err == persistent.ErrNotFound {
			// No upgrade pending, nothing to do.
			u.logger.Debug("no pending descriptors, continuing startup")
			return nil
		}
		return fmt.Errorf("can't decode stored upgrade descriptors: %w", err)
	}

	for _, pu := range u.pending {
		if pu.IsCompleted() {
			continue
		}

		// By this point, the descriptor is valid and still pending.
		if pu.UpgradeHeight == api.InvalidUpgradeHeight {
			// Only allow the old binary to run before the upgrade epoch.
			if pu.SubmittingVersion != thisVersion {
				return api.ErrNewTooSoon
			}
			return nil
		}

		// Otherwise, the upgrade should proceed right now. Check that we have the right binary.
		if err = pu.Descriptor.EnsureCompatible(); err != nil {
			return err
		}

		// In case the previous startup was e.g. interrupted during the second part of the
		// upgrade, we need to make sure that we're the same version as the previous run.
		if pu.RunningVersion != "" && pu.RunningVersion != thisVersion {
			return api.ErrInvalidResumingVersion
		}

		// Everything checks out, fill in the blanks.
		pu.RunningVersion = thisVersion
	}

	if err = u.flushDescriptorLocked(); err != nil {
		return err
	}

	u.logger.Info("loaded pending upgrade metadata",
		"pending", u.pending,
	)

	return nil
}

// NOTE: Assumes lock is held.
func (u *upgradeManager) flushDescriptorLocked() error {
	// Delete the state if there's no pending upgrades.
	if len(u.pending) == 0 {
		if err := u.store.Delete(metadataStoreKey); err != persistent.ErrNotFound {
			return err
		}
		return nil
	}

	// Otherwise go over pending upgrades and check if any are completed.
	var pending []*api.PendingUpgrade
	for _, pu := range u.pending {
		if pu.IsCompleted() {
			u.logger.Info("upgrade completed, removing state",
				"name", pu.Descriptor.Name,
			)
			continue
		}
		pending = append(pending, pu)
	}
	u.pending = pending
	return u.store.PutCBOR(metadataStoreKey, u.pending)
}

func (u *upgradeManager) StartupUpgrade() error {
	u.lock.Lock()
	defer u.lock.Unlock()

	for _, pu := range u.pending {
		if pu.UpgradeHeight == api.InvalidUpgradeHeight {
			continue
		}
		if pu.HasStage(api.UpgradeStageStartup) {
			u.logger.Warn("startup upgrade already performed, skipping",
				"name", pu.Descriptor.Name,
				"submitted_by", pu.SubmittingVersion,
				"version", pu.RunningVersion,
			)
			continue
		}

		// Execute the statup stage.
		pu.PushStage(api.UpgradeStageStartup)
		u.logger.Warn("performing startup upgrade",
			"name", pu.Descriptor.Name,
			"submitted_by", pu.SubmittingVersion,
			"version", pu.RunningVersion,
			logging.LogEvent, api.LogEventStartupUpgrade,
		)
		migrationCtx := migrations.NewContext(pu, u.dataDir)
		handler := migrations.GetHandler(migrationCtx)
		if err := handler.StartupUpgrade(migrationCtx); err != nil {
			return err
		}
	}

	return u.flushDescriptorLocked()
}

func (u *upgradeManager) ConsensusUpgrade(privateCtx interface{}, currentEpoch epochtime.EpochTime, currentHeight int64) error {
	u.lock.Lock()
	defer u.lock.Unlock()

	for _, pu := range u.pending {
		// If we haven't reached the upgrade epoch yet, we run normally;
		// startup made sure we're an appropriate binary for that.
		if pu.UpgradeHeight == api.InvalidUpgradeHeight {
			if currentEpoch < pu.Descriptor.Epoch {
				return nil
			}
			pu.UpgradeHeight = currentHeight
			if err := u.flushDescriptorLocked(); err != nil {
				return err
			}
			return api.ErrStopForUpgrade
		}

		// If we're already past the upgrade height, then everything must be complete.
		if pu.UpgradeHeight < currentHeight {
			pu.PushStage(api.UpgradeStageConsensus)
			continue
		}

		if pu.UpgradeHeight > currentHeight {
			panic("consensus upgrade: UpgradeHeight is in the future but upgrade epoch seen already")
		}

		if !pu.HasStage(api.UpgradeStageConsensus) {
			u.logger.Warn("performing consensus upgrade",
				"name", pu.Descriptor.Name,
				"submitted_by", pu.SubmittingVersion,
				"version", pu.RunningVersion,
				logging.LogEvent, api.LogEventConsensusUpgrade,
			)

			migrationCtx := migrations.NewContext(pu, u.dataDir)
			handler := migrations.GetHandler(migrationCtx)
			if err := handler.ConsensusUpgrade(migrationCtx, privateCtx); err != nil {
				return err
			}
		}
	}

	return u.flushDescriptorLocked()
}

func (u *upgradeManager) Close() {
	_ = u.flushDescriptorLocked()
	u.store.Close()
}

// New constructs and returns a new upgrade manager. It also checks for and loads any
// pending upgrade descriptors; if this node is not the one intended to be run according
// to the loaded descriptor, New will return an error.
func New(store *persistent.CommonStore, dataDir string) (api.Backend, error) {
	svcStore, err := store.GetServiceStore(api.ModuleName)
	if err != nil {
		return nil, err
	}
	upgrader := &upgradeManager{
		store:   svcStore,
		dataDir: dataDir,
		logger:  logging.GetLogger(api.ModuleName),
	}

	if err := upgrader.checkStatus(); err != nil {
		return nil, err
	}

	return upgrader, nil
}
