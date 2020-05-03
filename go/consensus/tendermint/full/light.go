package full

import (
	"context"
	"fmt"

	tmstate "github.com/tendermint/tendermint/state"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// Implements LightClientBackend.
func (t *fullService) GetSignedHeader(ctx context.Context, height int64) (*consensusAPI.SignedHeader, error) {
	if err := t.ensureStarted(ctx); err != nil {
		return nil, err
	}

	commit, err := t.client.Commit(&height)
	if err != nil {
		return nil, fmt.Errorf("%w: tendermint: header query failed: %s", consensusAPI.ErrVersionNotFound, err.Error())
	}

	if commit.Header == nil {
		return nil, fmt.Errorf("tendermint: header is nil")
	}

	meta, err := commit.SignedHeader.ToProto().Marshal()
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to marshal signed header: %w", err)
	}

	return &consensusAPI.SignedHeader{
		Height: commit.Header.Height,
		Meta:   meta,
	}, nil
}

// Implements LightClientBackend.
func (t *fullService) GetValidatorSet(ctx context.Context, height int64) (*consensusAPI.ValidatorSet, error) {
	if err := t.ensureStarted(ctx); err != nil {
		return nil, err
	}

	// Don't use the client as that imposes stupid pagination. Access the state database directly.
	vals, err := tmstate.LoadValidators(t.stateDb, height)
	if err != nil {
		return nil, consensusAPI.ErrVersionNotFound
	}

	protoVals, err := vals.ToProto()
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to convert validators: %w", err)
	}
	meta, err := protoVals.Marshal()
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to marshal validators: %w", err)
	}

	return &consensusAPI.ValidatorSet{
		Height: height,
		Meta:   meta,
	}, nil
}

// Implements LightClientBackend.
func (t *fullService) GetParameters(ctx context.Context, height int64) (*consensusAPI.Parameters, error) {
	if err := t.ensureStarted(ctx); err != nil {
		return nil, err
	}

	params, err := t.client.ConsensusParams(&height)
	if err != nil {
		return nil, fmt.Errorf("%w: tendermint: consensus params query failed: %s", consensusAPI.ErrVersionNotFound, err.Error())
	}

	meta, err := params.ConsensusParams.Marshal()
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to marshal consensus params: %w", err)
	}

	return &consensusAPI.Parameters{
		Height: params.BlockHeight,
		Meta:   meta,
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
