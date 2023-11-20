package fixtures

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	beaconInterop "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon/state/interop"
	keymanagerInterop "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/state/interop"
	registryInterop "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state/interop"
	roothashInterop "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/state/interop"
	stakingInterop "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state/interop"
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

	// Use a dummy ABCI InitChain context, as SetConsensusParameters methods require a specific ABCI context.
	ctx = api.NewContext(ctx, api.ContextInitChain, time.Time{}, nil, nil, nil, 0, nil, 0)

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
	if err = roothashInterop.InitializeTestRoothashState(ctx, mkvsTree); err != nil {
		return nil, fmt.Errorf("consensus-mock: failed to initialize roothash state: %w", err)
	}
	_, testRoot.Hash, err = mkvsTree.Commit(ctx, common.Namespace{}, 1)
	if err != nil {
		return nil, fmt.Errorf("consensus-mock: failed to committ tree: %w", err)
	}
	if err = ndb.Finalize([]node.Root{testRoot}); err != nil {
		return nil, fmt.Errorf("consensus-mock: failed to finalize test root: %w", err)
	}

	return &testRoot, nil
}

func init() {
	Register(&consensusMockFixture)
}
