// Package api defines the interface exporting the upgrade infrastructure's functionality.
package api

import (
	"bytes"
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
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
)

var (
	// ErrStopForUpgrade is the error returned by the consensus upgrade function when it detects that
	// the consensus layer has reached the scheduled shutdown epoch and should be interrupted.
	ErrStopForUpgrade = errors.New(ModuleName, 1, "upgrade: reached upgrade epoch")

	// ErrAlreadyPending is the error returned from SubmitDescriptor when the specific upgrade is already pending.
	ErrAlreadyPending = errors.New(ModuleName, 5, "upgrade: submitted upgrade is already pending, can not resubmit descriptor")

	// ErrUpgradeInProgress is the error returned from CancelUpgrade when the upgrade being cancelled is already in progress.
	ErrUpgradeInProgress = errors.New(ModuleName, 6, "upgrade: can not cancel upgrade in progress")
)

// UpgradeMethod is an upgrade descriptor method.
type UpgradeMethod uint8

const (
	// UpgradeMethodInternal is the internal upgrade method, where the node
	// binary itself has the migration code.
	UpgradeMethodInternal UpgradeMethod = 1

	// UpgradeMethodInternalName is the name of the upgrade method.
	UpgradeMethodInternalName = "internal"
)

// String returns a string representation of a UpgradeMethod.
func (m UpgradeMethod) String() string {
	switch m {
	case UpgradeMethodInternal:
		return UpgradeMethodInternalName
	default:
		return fmt.Sprintf("[unknown upgrade method: %d]", m)
	}
}

// MarshalText encodes a UpgradeMethod into text form.
func (m UpgradeMethod) MarshalText() ([]byte, error) {
	switch m {
	case UpgradeMethodInternal:
		return []byte(UpgradeMethodInternalName), nil
	default:
		return nil, fmt.Errorf("invalid upgrade method: %d", m)
	}
}

// UnmarshalText decodes a text slice into an UpgradeMethod.
func (m *UpgradeMethod) UnmarshalText(text []byte) error {
	switch string(text) {
	case UpgradeMethodInternalName:
		*m = UpgradeMethodInternal
	default:
		return fmt.Errorf("invalid upgrade method: %s", string(text))
	}
	return nil
}

// Descriptor describes an upgrade.
type Descriptor struct {
	// Name is the name of the upgrade. It should be derived from the node version.
	Name string `json:"name"`
	// Method is the upgrade method that should be used for this upgrade.
	Method UpgradeMethod `json:"method"`
	// Identifier is the upgrade method specific upgrade identifier.
	Identifier cbor.RawMessage `json:"identifier"`
	// Epoch is the epoch at which the upgrade should happen.
	Epoch beacon.EpochTime `json:"epoch"`
}

// Equals compares descriptors for equality.
func (d *Descriptor) Equals(other *Descriptor) bool {
	if d.Name != other.Name {
		return false
	}
	if d.Method != other.Method {
		return false
	}
	if !bytes.Equal(d.Identifier, other.Identifier) {
		return false
	}
	if d.Epoch != other.Epoch {
		return false
	}
	return true
}

// ValidateBasic does basic validation checks of the upgrade descriptor.
func (d Descriptor) ValidateBasic() error {
	switch d.Method {
	case UpgradeMethodInternal:
		var descriptorVersion version.ProtocolVersions
		if err := cbor.Unmarshal(d.Identifier, &descriptorVersion); err != nil {
			return fmt.Errorf("can't decode descriptor upgrade identifier: %w", err)
		}
	default:
		return fmt.Errorf("invalid descriptor method: %v", d)
	}
	if d.Epoch < 1 {
		return fmt.Errorf("invalid descriptor epoch: %d", d.Epoch)
	}

	return nil
}

// EnsureCompatible checks if currently running binary is compatible with
// the upgrade descriptor.
func (d *Descriptor) EnsureCompatible() error {
	switch d.Method {
	case UpgradeMethodInternal:
		ownVersion := version.Versions

		var descriptorVersion version.ProtocolVersions
		if err := cbor.Unmarshal(d.Identifier, &descriptorVersion); err != nil {
			return fmt.Errorf("can't decode descriptor upgrade identifier: %w", err)
		}

		if !ownVersion.Compatible(descriptorVersion) {
			return fmt.Errorf("binary version not compatible: own: %s, required: %s", ownVersion, descriptorVersion)
		}
	default:
		return fmt.Errorf("invalid upgrade method: %d", d.Method)
	}
	return nil
}

// PendingUpgrade describes a currently pending upgrade and includes the
// submitted upgrade descriptor.
type PendingUpgrade struct {
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

	// CancelUpgrade cancels a specific pending upgrade, unless it is already in progress.
	CancelUpgrade(context.Context, *Descriptor) error

	// StartupUpgrade performs the startup portion of the upgrade.
	// It is idempotent with respect to the current upgrade descriptor.
	StartupUpgrade() error

	// ConsensusUpgrade performs the consensus portion of the upgrade.
	// It is idempotent with respect to the current upgrade descriptor.
	ConsensusUpgrade(interface{}, beacon.EpochTime, int64) error

	// Close cleans up any upgrader state and database handles.
	Close()
}
