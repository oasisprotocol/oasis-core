package full

import (
	"context"
	"fmt"

	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	coreState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci/state"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// Implements LightClientBackend.
func (t *fullService) GetLightBlock(ctx context.Context, height int64) (*consensusAPI.LightBlock, error) {
	if err := t.ensureStarted(ctx); err != nil {
		return nil, err
	}

	tmHeight, err := t.heightToTendermintHeight(height)
	if err != nil {
		return nil, err
	}
	commit, err := t.client.Commit(ctx, &tmHeight)
	if err != nil {
		return nil, fmt.Errorf("%w: tendermint: header query failed: %s", consensusAPI.ErrVersionNotFound, err.Error())
	}

	if commit.Header == nil {
		return nil, fmt.Errorf("tendermint: header is nil")
	}

	// Don't use the client as that imposes stupid pagination. Access the state database directly.
	vals, err := t.stateStore.LoadValidators(tmHeight)
	if err != nil {
		return nil, consensusAPI.ErrVersionNotFound
	}

	lb := tmtypes.LightBlock{
		SignedHeader: &commit.SignedHeader,
		ValidatorSet: vals,
	}
	protoLb, err := lb.ToProto()
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to convert light block: %w", err)
	}
	meta, err := protoLb.Marshal()
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to marshal light block: %w", err)
	}

	return &consensusAPI.LightBlock{
		Height: commit.Header.Height,
		Meta:   meta,
	}, nil
}

// Implements LightClientBackend.
func (t *fullService) GetParameters(ctx context.Context, height int64) (*consensusAPI.Parameters, error) {
	if err := t.ensureStarted(ctx); err != nil {
		return nil, err
	}

	tmHeight, err := t.heightToTendermintHeight(height)
	if err != nil {
		return nil, err
	}
	params, err := t.client.ConsensusParams(ctx, &tmHeight)
	if err != nil {
		return nil, fmt.Errorf("%w: tendermint: consensus params query failed: %s", consensusAPI.ErrVersionNotFound, err.Error())
	}
	meta, err := params.ConsensusParams.Marshal()
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to marshal consensus params: %w", err)
	}

	cs, err := coreState.NewImmutableState(ctx, t.mux.State(), height)
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to initialize core consensus state: %w", err)
	}
	cp, err := cs.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to fetch core consensus parameters: %w", err)
	}

	return &consensusAPI.Parameters{
		Height:     params.BlockHeight,
		Parameters: *cp,
		Meta:       meta,
	}, nil
}

// Implements LightClientBackend.
func (t *fullService) State() syncer.ReadSyncer {
	return t.mux.State().Storage()
}

// Implements LightClientBackend.
func (t *fullService) SubmitTxNoWait(ctx context.Context, tx *transaction.SignedTransaction) error {
	return t.broadcastTxRaw(cbor.Marshal(tx))
}
