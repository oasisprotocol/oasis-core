// Package api defines the interface exporting the upgrade infrastructure's functionality.
package api

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
)

const (
	// ModuleName is the upgrade module name.
	ModuleName = "upgrade"

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

	// ErrAlreadyPending is the error returned from SubmitDescriptor when the specific upgrade is already pending.
	ErrAlreadyPending = errors.New(ModuleName, 5, "upgrade: submitted upgrade is already pending, can not resubmit descriptor")

	// ErrUpgradeInProgress is the error returned from CancelUpgrade when the upgrade being cancelled is already in progress.
	ErrUpgradeInProgress = errors.New(ModuleName, 6, "upgrade: can not cancel upgrade in progress")
)

// OwnHash returns the hash of the executable that started the current process.
func OwnHash() (*hash.Hash, error) {
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
	// Identifier is a hash of the binary to be used for upgrading.
	Identifier string `json:"identifier"`
	// Epoch is the epoch at which the upgrade should happen.
	Epoch epochtime.EpochTime `json:"epoch"`
}

// Equals compares descriptors for equality.
func (d *Descriptor) Equals(other *Descriptor) bool {
	if d.Name != other.Name {
		return false
	}
	if d.Method != other.Method {
		return false
	}
	if d.Identifier != other.Identifier {
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
		// For internal upgrade method the identifier needs to be a valid hex encoded hash.
		var idHash hash.Hash
		if err := idHash.UnmarshalHex(d.Identifier); err != nil {
			return fmt.Errorf("invalid internal upgrade descriptor identifier: %s: %w", d.Identifier, err)
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
		// For Internal upgrade method, the current binary hash needs to match the
		// descriptor identifier.
		OwnHash, err := OwnHash()
		if err != nil {
			return fmt.Errorf("error obtaining own binary hash: %w", err)
		}

		var descriptorHash hash.Hash
		if err = descriptorHash.UnmarshalHex(d.Identifier); err != nil {
			return fmt.Errorf("can't decode stored upgrade identifier: %w", err)
		}

		if !OwnHash.Equal(&descriptorHash) {
			return fmt.Errorf("binary hash missmatch: own: %d, required: %d", OwnHash, descriptorHash)
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

	// PendingUpgrades returns pending upgrades.
	PendingUpgrades(context.Context) ([]*PendingUpgrade, error)

	// CancelUpgrade cancels a specific pending upgrade, unless it is already in progress.
	CancelUpgrade(ctx context.Context, name string) error

	// StartupUpgrade performs the startup portion of the upgrade.
	// It is idempotent with respect to the current upgrade descriptor.
	StartupUpgrade() error

	// ConsensusUpgrade performs the consensus portion of the upgrade.
	// It is idempotent with respect to the current upgrade descriptor.
	ConsensusUpgrade(interface{}, epochtime.EpochTime, int64) error

	// Close cleans up any upgrader state and database handles.
	Close()
}
