package full

import (
	"context"
	"fmt"
	"sync"

	tmstate "github.com/tendermint/tendermint/state"
	tmstatesync "github.com/tendermint/tendermint/statesync"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/light"
)

type stateProvider struct {
	sync.Mutex

	lc              light.Client
	genesisDocument *tmtypes.GenesisDoc

	logger *logging.Logger
}

// Implements tmstatesync.StateProvider.
func (sp *stateProvider) AppHash(ctx context.Context, height uint64) ([]byte, error) {
	sp.Lock()
	defer sp.Unlock()

	// We have to fetch the next height, which contains the app hash for the previous height.
	lb, err := sp.lc.GetVerifiedLightBlock(ctx, int64(height+1))
	if err != nil {
		return nil, err
	}
	return lb.AppHash, nil
}

// Implements tmstatesync.StateProvider.
func (sp *stateProvider) Commit(ctx context.Context, height uint64) (*tmtypes.Commit, error) {
	sp.Lock()
	defer sp.Unlock()

	lb, err := sp.lc.GetVerifiedLightBlock(ctx, int64(height))
	if err != nil {
		return nil, err
	}
	return lb.Commit, nil
}

// Implements tmstatesync.StateProvider.
func (sp *stateProvider) State(ctx context.Context, height uint64) (tmstate.State, error) {
	sp.Lock()
	defer sp.Unlock()

	state := tmstate.State{
		ChainID:       sp.genesisDocument.ChainID,
		Version:       tmstate.InitStateVersion,
		InitialHeight: sp.genesisDocument.InitialHeight,
	}
	// XXX: This will fail in case an upgrade happened in-between.
	state.Version.Consensus.App = version.TendermintAppVersion

	// The snapshot height maps onto the state heights as follows:
	//
	// height: last block, i.e. the snapshotted height
	// height+1: current block, i.e. the first block we'll process after the snapshot
	// height+2: next block, i.e. the second block after the snapshot
	//
	// We need to fetch the NextValidators from height+2 because if the application changed
	// the validator set at the snapshot height then this only takes effect at height+2.
	lastLightBlock, err := sp.lc.GetVerifiedLightBlock(ctx, int64(height))
	if err != nil {
		return tmstate.State{}, err
	}
	curLightBlock, err := sp.lc.GetVerifiedLightBlock(ctx, int64(height)+1)
	if err != nil {
		return tmstate.State{}, err
	}
	nextLightBlock, err := sp.lc.GetVerifiedLightBlock(ctx, int64(height)+2)
	if err != nil {
		return tmstate.State{}, err
	}
	state.LastBlockHeight = lastLightBlock.Height
	state.LastBlockTime = lastLightBlock.Time
	state.LastBlockID = lastLightBlock.Commit.BlockID
	state.AppHash = curLightBlock.AppHash
	state.LastResultsHash = curLightBlock.LastResultsHash
	state.LastValidators = lastLightBlock.ValidatorSet
	state.Validators = curLightBlock.ValidatorSet
	state.NextValidators = nextLightBlock.ValidatorSet
	state.LastHeightValidatorsChanged = nextLightBlock.Height

	// Fetch consensus parameters with light client verification.
	params, err := sp.lc.GetVerifiedParameters(ctx, nextLightBlock.Height)
	if err != nil {
		return tmstate.State{}, fmt.Errorf("failed to fetch consensus parameters for height %d: %w",
			nextLightBlock.Height,
			err,
		)
	}
	state.ConsensusParams = *params

	return state, nil
}

func newStateProvider(ctx context.Context, cfg light.ClientConfig) (tmstatesync.StateProvider, error) {
	lc, err := light.NewClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return &stateProvider{
		lc:              lc,
		genesisDocument: cfg.GenesisDocument,
		logger:          logging.GetLogger("consensus/tendermint/stateprovider"),
	}, nil
}
