package fixtures

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	beaconInterop "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon/state/interop"
	keymanagerInterop "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/keymanager/state/interop"
	registryInterop "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state/interop"
	stakingInterop "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state/interop"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const consensusMockName = "consensus_mock"

var consensusMockFixture = consensusMock{}

type consensusMock struct{}

func (c *consensusMock) Name() string {
	return consensusMockName
}

func (c *consensusMock) Populate(ctx context.Context, ndb db.NodeDB) (*node.Root, error) {
	var err error
	testRoot := storage.Root{
		Type:    storage.RootTypeState,
		Version: 1,
	}

	mkvsTree := mkvs.New(nil, ndb, node.RootTypeState, mkvs.WithoutWriteLog())
	if err = stakingInterop.InitializeTestStakingState(ctx, mkvsTree); err != nil {
		return nil, fmt.Errorf("consensus-mock: failed to initialize staking state: %w", err)
	}
	if err = beaconInterop.InitializeTestBeaconState(ctx, mkvsTree); err != nil {
		return nil, fmt.Errorf("consensus-mock: failed to initialize beacon state: %w", err)
	}
	if err = registryInterop.InitializeTestRegistryState(ctx, mkvsTree); err != nil {
		return nil, fmt.Errorf("consensus-mock: failed to initialize registry state: %w", err)
	}
	if err = keymanagerInterop.InitializeTestKeyManagerState(ctx, mkvsTree); err != nil {
		return nil, fmt.Errorf("consensus-mock: failed to initialize key manager state: %w", err)
	}
	_, testRoot.Hash, err = mkvsTree.Commit(ctx, common.Namespace{}, 1)
	if err != nil {
		return nil, fmt.Errorf("consensus-mock: failed to committ tree: %w", err)
	}
	if err = ndb.Finalize(ctx, []node.Root{testRoot}); err != nil {
		return nil, fmt.Errorf("consensus-mock: failed to finalize test root: %w", err)
	}

	return &testRoot, nil
}

func init() {
	Register(&consensusMockFixture)
}
