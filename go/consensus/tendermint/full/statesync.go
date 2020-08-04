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

	ctx             context.Context
	lc              light.Client
	genesisDocument *tmtypes.GenesisDoc

	logger *logging.Logger
}

// Implements tmstatesync.StateProvider.
func (sp *stateProvider) AppHash(height uint64) ([]byte, error) {
	sp.Lock()
	defer sp.Unlock()

	// We have to fetch the next height, which contains the app hash for the previous height.
	header, err := sp.lc.GetVerifiedSignedHeader(sp.ctx, int64(height+1))
	if err != nil {
		return nil, err
	}
	return header.AppHash, nil
}

// Implements tmstatesync.StateProvider.
func (sp *stateProvider) Commit(height uint64) (*tmtypes.Commit, error) {
	sp.Lock()
	defer sp.Unlock()

	header, err := sp.lc.GetVerifiedSignedHeader(sp.ctx, int64(height))
	if err != nil {
		return nil, err
	}
	return header.Commit, nil
}

// Implements tmstatesync.StateProvider.
func (sp *stateProvider) State(height uint64) (tmstate.State, error) {
	sp.Lock()
	defer sp.Unlock()

	state := tmstate.State{
		ChainID: sp.genesisDocument.ChainID,
		Version: tmstate.InitStateVersion,
	}
	// XXX: This will fail in case an upgrade happened inbetween.
	state.Version.Consensus.App = version.ConsensusProtocol.ToU64()

	// We need to verify up until h+2, to get the validator set. This also prefetches the headers
	// for h and h+1 in the typical case where the trusted header is after the snapshot height.
	_, err := sp.lc.GetVerifiedSignedHeader(sp.ctx, int64(height+2))
	if err != nil {
		return tmstate.State{}, err
	}
	header, err := sp.lc.GetVerifiedSignedHeader(sp.ctx, int64(height))
	if err != nil {
		return tmstate.State{}, err
	}
	nextHeader, err := sp.lc.GetVerifiedSignedHeader(sp.ctx, int64(height+1))
	if err != nil {
		return tmstate.State{}, err
	}
	state.LastBlockHeight = header.Height
	state.LastBlockTime = header.Time
	state.LastBlockID = header.Commit.BlockID
	state.AppHash = nextHeader.AppHash
	state.LastResultsHash = nextHeader.LastResultsHash

	state.LastValidators, _, err = sp.lc.GetVerifiedValidatorSet(sp.ctx, int64(height))
	if err != nil {
		return tmstate.State{}, err
	}
	state.Validators, _, err = sp.lc.GetVerifiedValidatorSet(sp.ctx, int64(height+1))
	if err != nil {
		return tmstate.State{}, err
	}
	state.NextValidators, _, err = sp.lc.GetVerifiedValidatorSet(sp.ctx, int64(height+2))
	if err != nil {
		return tmstate.State{}, err
	}
	state.LastHeightValidatorsChanged = int64(height)

	// Fetch consensus parameters with light client verification.
	params, err := sp.lc.GetVerifiedParameters(sp.ctx, nextHeader.Height)
	if err != nil {
		return tmstate.State{}, fmt.Errorf("failed to fetch consensus parameters for height %d: %w",
			nextHeader.Height,
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
		ctx:             ctx,
		lc:              lc,
		genesisDocument: cfg.GenesisDocument,
		logger:          logging.GetLogger("consensus/tendermint/stateprovider"),
	}, nil
}
