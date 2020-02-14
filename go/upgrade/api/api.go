// Package api defines the interface exporting the upgrade infrastructure's functionality.
package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/errors"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

const (
	// ModuleName is the upgrade module name.
	ModuleName = "upgrade"

	// UpgradeMethInternal is the internal upgrade method,
	// where the node binary itself has the migration code.
	UpgradeMethInternal = "internal"

	// LogEventStartupUpgrade is a log event value that signals the startup upgrade handler was called.
	LogEventStartupUpgrade = "dummy-migration/startup-upgrade"
	// LogEventConsensusUpgrade is a log event value that signals the consensus upgrade handler was called.
	LogEventConsensusUpgrade = "dummy-migration/consensus-upgrade"
)

// UpgradeStage is used in the upgrade descriptor to store completed stages.
type UpgradeStage uint64

const (
	// UpgradeStageStartup is the startup upgrade stage, executed at the beginning of node startup.
	UpgradeStageStartup UpgradeStage = 1

	// UpgradeStageConsensus is the upgrade stage carried out during consensus events.
	UpgradeStageConsensus UpgradeStage = 2

	upgradeStageLast = UpgradeStageConsensus

	// InvalidUpgradeHeight means the upgrade epoch hasn't been reached yet.
	InvalidUpgradeHeight = int64(0)
)

var (
	// ErrStopForUpgrade is the error returned by the consensus upgrade function when it detects that
	// the consensus layer has reached the scheduled shutdown epoch and should be interrupted.
	ErrStopForUpgrade = errors.New(ModuleName, 1, "upgrade: reached upgrade epoch")

	// ErrUpgradePending is the error returned when there is a pending upgrade and the node detects that it is
	// not the one performing it.
	ErrUpgradePending = errors.New(ModuleName, 2, "upgrade: this binary is scheduled to be replaced")

	// ErrNewTooSoon is the error returned when the node started isn't the pre-upgrade version and the upgrade
	// epoch hasn't been reached yet.
	ErrNewTooSoon = errors.New(ModuleName, 3, "upgrade: running different binary before reaching the upgrade epoch")

	// ErrInvalidResumingVersion is the error returned when the running node's version is different from the one that
	// started performing the upgrade.
	ErrInvalidResumingVersion = errors.New(ModuleName, 4, "upgrade: node restarted mid-upgrade with different version")

	// ErrAlreadyPending is the error returned from SubmitDescriptor when there is already an upgrade pending.
	ErrAlreadyPending = errors.New(ModuleName, 5, "upgrade: an upgrade is already pending, can not submit new descriptor")

	// ErrUpgradeInProgress is the error returned from CancelUpgrade when the upgrade being cancelled is already in progress.
	ErrUpgradeInProgress = errors.New(ModuleName, 6, "upgrade: can not cancel upgrade in progress")
)

// Descriptor describes an upgrade.
type Descriptor struct {
	// Name is the name of the upgrade. It should be derived from the node version.
	Name string `json:"name"`
	// Method is the upgrade method that should be used for this upgrade.
	Method string `json:"method"`
	// Identifier is a hash of the binary to be used for upgrading.
	// Upgrade methods other than "internal" may have differently formatted identifiers.
	Identifier string `json:"identifier"`
	// Epoch is the epoch at which the upgrade should happen.
	Epoch epochtime.EpochTime `json:"epoch"`
}

// IsValid checks if the upgrade descriptor is valid.
func (d Descriptor) IsValid() bool {
	if d.Method != UpgradeMethInternal {
		return false
	}
	if d.Epoch < 1 {
		return false
	}
	return true
}

// PendingUpgrade describes a currently pending upgrade and includes the
// submitted upgrade descriptor.
type PendingUpgrade struct {
	// Descriptor is the upgrade descriptor describing the upgrade.
	Descriptor *Descriptor `json:"descriptor"`

	// SubmittingVersion is the version of the node used to submit the descriptor.
	SubmittingVersion string `json:"submitting_version"`
	// RunningVersion is the version of the node trying to execute the descriptor.
	RunningVersion string `json:"running_version"`

	// UpgradeHeight is the height at which the upgrade epoch was reached
	// (or InvalidUpgradeHeight if it hasn't been reached yet).
	UpgradeHeight int64 `json:"upgrade_height"`

	// LastCompletedStage is the last upgrade stage that was successfully completed.
	LastCompletedStage UpgradeStage `json:"last_completed_stage"`
}

// IsCompleted checks if all upgrade stages were already completed.
func (pu PendingUpgrade) IsCompleted() bool {
	return pu.LastCompletedStage >= upgradeStageLast
}

// HasAnyStages checks if any stages were completed at all.
func (pu PendingUpgrade) HasAnyStages() bool {
	return pu.LastCompletedStage > 0
}

// HasStage checks if a given stage has been completed or not.
func (pu PendingUpgrade) HasStage(stage UpgradeStage) bool {
	return pu.LastCompletedStage >= stage
}

// PushStage marks the given stage as completed.
func (pu *PendingUpgrade) PushStage(stage UpgradeStage) {
	if pu.LastCompletedStage+1 != stage {
		panic("upgrade: out of order upgrade stage execution")
	}
	pu.LastCompletedStage = stage
}

// Backend defines the interface for upgrade managers.
type Backend interface {
	// SubmitDescriptor submits the serialized descriptor to the upgrade manager
	// which then schedules and manages the upgrade.
	SubmitDescriptor(context.Context, *Descriptor) error

	// CancelUpgrade cancels a pending upgrade, unless it is already in progress.
	CancelUpgrade(context.Context) error

	// StartupUpgrade performs the startup portion of the upgrade.
	// It is idempotent with respect to the current upgrade descriptor.
	StartupUpgrade() error

	// ConsensusUpgrade performs the consensus portion of the upgrade.
	// It is idempotent with respect to the current upgrade descriptor.
	ConsensusUpgrade(interface{}, epochtime.EpochTime, int64) error

	// Close cleans up any upgrader state and database handles.
	Close()
}
