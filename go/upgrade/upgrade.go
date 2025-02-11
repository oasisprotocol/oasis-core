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
	"io/ioutil"
	"os"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade/migrations"
)

var (
	_ api.Backend = (*upgradeManager)(nil)

	metadataStoreKey = []byte("descriptor")

	thisVersion = makeVersionString()
)

func hashSelf() (*hash.Hash, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}

	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	h := hash.NewFromBytes(contents)
	return &h, nil
}

func makeVersionString() string {
	return version.SoftwareVersion
}

type upgradeManager struct {
	store   *persistent.ServiceStore
	pending *api.PendingUpgrade
	lock    sync.Mutex

	ctx     *migrations.Context
	handler migrations.Handler

	logger *logging.Logger
}

func (u *upgradeManager) SubmitDescriptor(ctx context.Context, descriptor *api.Descriptor) error {
	u.lock.Lock()
	defer u.lock.Unlock()

	if u.pending != nil {
		return api.ErrAlreadyPending
	}

	u.pending = &api.PendingUpgrade{
		Descriptor: descriptor,
	}
	u.pending.SubmittingVersion = thisVersion

	u.logger.Info("received upgrade descriptor, scheduling shutdown",
		"name", u.pending.Descriptor.Name,
		"epoch", u.pending.Descriptor.Epoch,
	)

	return u.flushDescriptor()
}

func (u *upgradeManager) CancelUpgrade(ctx context.Context) error {
	u.lock.Lock()
	defer u.lock.Unlock()

	if u.pending == nil {
		// Make sure nothing is saved.
		return u.flushDescriptor()
	}

	if u.pending.RunningVersion != "" || u.pending.UpgradeHeight != api.InvalidUpgradeHeight || u.pending.HasAnyStages() {
		return api.ErrUpgradeInProgress
	}

	oldPending := u.pending
	u.pending = nil
	if err := u.flushDescriptor(); err != nil {
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
			u.logger.Debug("no pending descriptor, continuing startup")
			return nil
		}
		return fmt.Errorf("can't decode stored upgrade descriptor: %w", err)
	}

	if u.pending.IsCompleted() {
		// This technically shouldn't happen, but isn't really an error either.
		return u.flushDescriptor()
	}

	// By this point, the descriptor is valid and still pending.
	if u.pending.UpgradeHeight == api.InvalidUpgradeHeight {
		// Only allow the old binary to run before the upgrade epoch.
		if u.pending.SubmittingVersion != thisVersion {
			return api.ErrNewTooSoon
		}
		return nil
	}

	// Otherwise, the upgrade should proceed right now. Check that we're the right binary.
	thisHash, err := hashSelf()
	if err != nil {
		return err
	}

	var upgraderHash hash.Hash
	if err = upgraderHash.UnmarshalHex(u.pending.Descriptor.Identifier); err != nil {
		return fmt.Errorf("can't decode stored upgrade identifier: %w", err)
	}

	if !thisHash.Equal(&upgraderHash) {
		return api.ErrUpgradePending
	}

	// In case the previous startup was e.g. interruptd during the second part of the
	// upgrade, we need to make sure that we're the same version as the previous run.
	if u.pending.RunningVersion != "" && u.pending.RunningVersion != thisVersion {
		return api.ErrInvalidResumingVersion
	}

	// Everything checks out, fill in the blanks.
	u.pending.RunningVersion = thisVersion
	_ = u.flushDescriptor()
	u.logger.Info("loaded pending upgrade metadata",
		"name", u.pending.Descriptor.Name,
		"last_stage", u.pending.LastCompletedStage,
	)
	return nil
}

func (u *upgradeManager) flushDescriptor() error {
	if u.pending == nil {
		if err := u.store.Delete(metadataStoreKey); err != persistent.ErrNotFound {
			return err
		}
		return nil
	}
	if u.pending.IsCompleted() {
		u.logger.Info("upgrade completed, removing state",
			"name", u.pending.Descriptor.Name,
		)
		err := u.store.Delete(metadataStoreKey)
		if err == nil {
			u.pending = nil
		}
		return err
	}
	return u.store.PutCBOR(metadataStoreKey, &u.pending)
}

func (u *upgradeManager) StartupUpgrade() error {
	u.lock.Lock()
	defer u.lock.Unlock()

	if u.pending == nil || u.pending.UpgradeHeight == api.InvalidUpgradeHeight {
		return nil
	}
	if !u.pending.HasStage(api.UpgradeStageStartup) {
		// Make sure we're in order (pushing will panic otherwise).
		u.pending.PushStage(api.UpgradeStageStartup)

		u.logger.Warn("performing startup upgrade",
			"name", u.pending.Descriptor.Name,
			"submitted_by", u.pending.SubmittingVersion,
			"version", u.pending.RunningVersion,
			logging.LogEvent, api.LogEventStartupUpgrade,
		)
		err := u.handler.StartupUpgrade(u.ctx)
		if err == nil {
			// Save the updated descriptor state.
			err = u.flushDescriptor()
		}
		return err
	}
	u.logger.Warn("startup upgrade already performed, skipping",
		"name", u.pending.Descriptor.Name,
		"submitted_by", u.pending.SubmittingVersion,
		"version", u.pending.RunningVersion,
	)
	return nil
}

func (u *upgradeManager) ConsensusUpgrade(privateCtx interface{}, currentEpoch epochtime.EpochTime, currentHeight int64) error {
	u.lock.Lock()
	defer u.lock.Unlock()

	if u.pending == nil {
		return nil
	}

	// If we haven't reached the upgrade epoch yet, we run normally;
	// startup made sure we're an appropriate binary for that.
	if u.pending.UpgradeHeight == api.InvalidUpgradeHeight {
		if currentEpoch < u.pending.Descriptor.Epoch {
			return nil
		}
		u.pending.UpgradeHeight = currentHeight
		if err := u.flushDescriptor(); err != nil {
			return err
		}
		return api.ErrStopForUpgrade
	}

	// If we're already past the upgrade height, then everything must be complete.
	if u.pending.UpgradeHeight < currentHeight {
		u.pending.PushStage(api.UpgradeStageConsensus)
		return u.flushDescriptor()
	}

	if u.pending.UpgradeHeight > currentHeight {
		panic("consensus upgrade: UpgradeHeight is in the future but upgrade epoch seen already")
	}

	if !u.pending.HasStage(api.UpgradeStageConsensus) {
		u.logger.Warn("performing consensus upgrade",
			"name", u.pending.Descriptor.Name,
			"submitted_by", u.pending.SubmittingVersion,
			"version", u.pending.RunningVersion,
			logging.LogEvent, api.LogEventConsensusUpgrade,
		)
		return u.handler.ConsensusUpgrade(u.ctx, privateCtx)
	}
	return nil
}

func (u *upgradeManager) Close() {
	_ = u.flushDescriptor()
	u.store.Close()
}

// New constructs and returns a new upgrade manager. It also checks for and loads any
// pending upgrade descriptors; if this node is not the one intended to be run according
// to the loaded descriptor, New will return an error.
func New(store *persistent.CommonStore, dataDir string, checkStatus bool) (api.Backend, error) {
	svcStore, err := store.GetServiceStore(api.ModuleName)
	if err != nil {
		return nil, err
	}
	upgrader := &upgradeManager{
		store:  svcStore,
		logger: logging.GetLogger(api.ModuleName),
	}

	if checkStatus {
		if err := upgrader.checkStatus(); err != nil {
			return nil, err
		}
	}

	if upgrader.pending != nil {
		upgrader.ctx = migrations.NewContext(upgrader.pending, dataDir)
		upgrader.handler = migrations.GetHandler(upgrader.ctx)
	}

	return upgrader, nil
}
