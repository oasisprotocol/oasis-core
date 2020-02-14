package upgrade

import (
	"context"

	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/upgrade/api"
)

var (
	_ api.Backend = (*dummyUpgradeManager)(nil)
)

type dummyUpgradeManager struct{}

func (u *dummyUpgradeManager) SubmitDescriptor(ctx context.Context, descriptor *api.Descriptor) error {
	return nil
}

func (u *dummyUpgradeManager) CancelUpgrade(ctx context.Context) error {
	return nil
}

func (u *dummyUpgradeManager) StartupUpgrade() error {
	return nil
}

func (u *dummyUpgradeManager) ConsensusUpgrade(privateCtx interface{}, currentEpoch epochtime.EpochTime, currentHeight int64) error {
	return nil
}

func (u *dummyUpgradeManager) Close() {
}

// NewDummyUpgradeManager creates and returns a new dummy upgrade manager.
func NewDummyUpgradeManager() api.Backend {
	return &dummyUpgradeManager{}
}
