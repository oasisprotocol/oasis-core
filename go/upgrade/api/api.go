// Package api defines the interface exporting the upgrade infrastructure's functionality.
package api

import (
	"context"
	"fmt"
	"io"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

const (
	// ModuleName is the upgrade module name.
	ModuleName = "upgrade"

	// LogEventIncompatibleBinary is a log event value that signals the currently running version
	// of the binary is incompatible with the upgrade.
	LogEventIncompatibleBinary = "upgrade/incompatible-binary"
	// LogEventStartupUpgrade is a log event value that signals the startup upgrade handler was
	// called.
	LogEventStartupUpgrade = "upgrade/startup-upgrade"
	// LogEventConsensusUpgrade is a log event value that signals the consensus upgrade handler was
	// called.
	LogEventConsensusUpgrade = "upgrade/consensus-upgrade"
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

	// LatestDescriptorVersion is the latest upgrade descriptor version that should be used for
	// descriptors.
	LatestDescriptorVersion = 1

	// Minimum and maximum descriptor versions that are allowed.
	minDescriptorVersion = 1
	maxDescriptorVersion = LatestDescriptorVersion

	// LatestPendingUpgradeVersion is the latest pending upgrade struct version.
	LatestPendingUpgradeVersion = 1
)

var (
	// ErrStopForUpgrade is the error returned by the consensus upgrade function when it detects that
	// the consensus layer has reached the scheduled shutdown epoch and should be interrupted.
	ErrStopForUpgrade = errors.New(ModuleName, 1, "upgrade: reached upgrade epoch")

	// ErrAlreadyPending is the error returned from SubmitDescriptor when the specific upgrade is already pending.
	ErrAlreadyPending = errors.New(ModuleName, 5, "upgrade: submitted upgrade is already pending, can not resubmit descriptor")

	// ErrUpgradeInProgress is the error returned from CancelUpgrade when the upgrade being cancelled is already in progress.
	ErrUpgradeInProgress = errors.New(ModuleName, 6, "upgrade: can not cancel upgrade in progress")

	_ prettyprint.PrettyPrinter = (*Descriptor)(nil)
)

// Descriptor describes an upgrade.
type Descriptor struct { // nolint: maligned
	cbor.Versioned

	// Handler is the name of the upgrade handler.
	Handler string `json:"handler"`
	// Target is upgrade's target version.
	Target version.ProtocolVersions `json:"target"`
	// Epoch is the epoch at which the upgrade should happen.
	Epoch beacon.EpochTime `json:"epoch"`
}

// Equals compares descriptors for equality.
func (d *Descriptor) Equals(other *Descriptor) bool {
	if d.V != other.V {
		return false
	}
	if d.Handler != other.Handler {
		return false
	}
	if d.Target != other.Target {
		return false
	}
	if d.Epoch != other.Epoch {
		return false
	}
	return true
}

// ValidateBasic does basic validation checks of the upgrade descriptor.
func (d Descriptor) ValidateBasic() error {
	if d.V < minDescriptorVersion || d.V > maxDescriptorVersion {
		return fmt.Errorf("invalid upgrade descriptor version (min: %d max: %d)",
			minDescriptorVersion,
			maxDescriptorVersion,
		)
	}
	if d.Handler == "" {
		return fmt.Errorf("empty descriptor handler")
	}
	empty := version.ProtocolVersions{}
	if d.Target == empty {
		return fmt.Errorf("empty target version")
	}
	if d.Epoch < 1 {
		return fmt.Errorf("invalid descriptor epoch: %d", d.Epoch)
	}

	return nil
}

// EnsureCompatible checks if currently running binary is compatible with
// the upgrade descriptor.
func (d *Descriptor) EnsureCompatible() error {
	ownVersion := version.Versions

	if !ownVersion.Compatible(d.Target) {
		return fmt.Errorf("binary version not compatible: own: %s, required: %s", ownVersion, d.Target)
	}
	return nil
}

// PrettyPrint writes a pretty-printed representation of Descriptor to the given
// writer.
func (d Descriptor) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sHandler: %s\n", prefix, d.Handler)
	fmt.Fprintf(w, "%sTarget Version:\n", prefix)
	d.Target.PrettyPrint(ctx, prefix+"  ", w)
	fmt.Fprintf(w, "%sEpoch: %d\n", prefix, d.Epoch)
}

// PrettyType returns a representation of Descriptor that can be used for pretty
// printing.
func (d Descriptor) PrettyType() (interface{}, error) {
	return d, nil
}

// PendingUpgrade describes a currently pending upgrade and includes the
// submitted upgrade descriptor.
type PendingUpgrade struct {
	cbor.Versioned

	// Descriptor is the upgrade descriptor describing the upgrade.
	Descriptor *Descriptor `json:"descriptor"`

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

	// PendingUpgrades returns pending upgrades.
	PendingUpgrades(context.Context) ([]*PendingUpgrade, error)

	// HasPendingUpgradeAt returns whether there is a pending upgrade at a specified height.
	HasPendingUpgradeAt(context.Context, int64) (bool, error)

	// CancelUpgrade cancels a specific pending upgrade, unless it is already in progress.
	CancelUpgrade(context.Context, *Descriptor) error

	// StartupUpgrade performs the startup portion of the upgrade.
	// It is idempotent with respect to the current upgrade descriptor.
	StartupUpgrade() error

	// ConsensusUpgrade performs the consensus portion of the upgrade. Note that this will be called
	// multiple times (in BeginBlock and EndBlock) where the context in the first argument can be
	// used to determine which part it is.
	//
	// It is idempotent with respect to the current upgrade descriptor.
	ConsensusUpgrade(interface{}, beacon.EpochTime, int64) error

	// Close cleans up any upgrader state and database handles.
	Close()
}
