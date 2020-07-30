package full

import (
	"context"
	"fmt"

	tmamino "github.com/tendermint/go-amino"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmstate "github.com/tendermint/tendermint/state"

	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// We must use Tendermint's amino codec as some Tendermint's types are not easily unmarshallable.
var aminoCodec = tmamino.NewCodec()

func init() {
	tmrpctypes.RegisterAmino(aminoCodec)
}

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

	return &consensusAPI.SignedHeader{
		Height: commit.Header.Height,
		Meta:   aminoCodec.MustMarshalBinaryBare(commit.SignedHeader),
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

	return &consensusAPI.ValidatorSet{
		Height: height,
		Meta:   aminoCodec.MustMarshalBinaryBare(vals),
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

	return &consensusAPI.Parameters{
		Height: params.BlockHeight,
		Meta:   aminoCodec.MustMarshalBinaryBare(params.ConsensusParams),
	}, nil
}

// Implements LightClientBackend.
func (t *fullService) State() syncer.ReadSyncer {
	return t.mux.State().Storage()
}
