package upgrade

import (
	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

var _ api.Backend = (*dummyUpgradeManager)(nil)

type dummyUpgradeManager struct{}

func (u *dummyUpgradeManager) SubmitDescriptor(*api.Descriptor) error {
	return nil
}

func (u *dummyUpgradeManager) PendingUpgrades() ([]*api.PendingUpgrade, error) {
	return nil, nil
}

func (u *dummyUpgradeManager) HasPendingUpgradeAt(int64) (bool, error) {
	return false, nil
}

func (u *dummyUpgradeManager) CancelUpgrade(*api.Descriptor) error {
	return nil
}

func (u *dummyUpgradeManager) GetUpgrade(*api.Descriptor) (*api.PendingUpgrade, error) {
	return nil, api.ErrUpgradeNotFound
}

func (u *dummyUpgradeManager) StartupUpgrade() error {
	return nil
}

func (u *dummyUpgradeManager) ConsensusUpgrade(interface{}, beacon.EpochTime, int64) error {
	return nil
}

func (u *dummyUpgradeManager) Close() {
}

// NewDummyUpgradeManager creates and returns a new dummy upgrade manager.
func NewDummyUpgradeManager() api.Backend {
	return &dummyUpgradeManager{}
}
