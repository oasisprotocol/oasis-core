package full

import (
	"context"
	"fmt"

	tmcore "github.com/tendermint/tendermint/rpc/core"
	tmstate "github.com/tendermint/tendermint/state"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// Implements LightClientBackend.
func (n *commonNode) GetLightBlock(ctx context.Context, height int64) (*consensusAPI.LightBlock, error) {
	if err := n.ensureStarted(ctx); err != nil {
		return nil, err
	}

	tmHeight, err := n.heightToTendermintHeight(height)
	if err != nil {
		return nil, err
	}

	// Don't use the client as that imposes stupid pagination. Access the state database directly.
	vals, err := tmstate.LoadValidators(n.stateStore, tmHeight)
	if err != nil {
		return nil, consensusAPI.ErrVersionNotFound
	}

	commit, err := tmcore.Commit(n.rpcCtx, &height)
	if err != nil {
		return nil, fmt.Errorf("%w: tendermint: header query failed: %s", consensusAPI.ErrVersionNotFound, err.Error())
	}

	if commit.Header == nil {
		return nil, fmt.Errorf("tendermint: header is nil")
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
func (n *commonNode) GetParameters(ctx context.Context, height int64) (*consensusAPI.Parameters, error) {
	if err := n.ensureStarted(ctx); err != nil {
		return nil, err
	}

	tmHeight, err := n.heightToTendermintHeight(height)
	if err != nil {
		return nil, err
	}

	// Query consensus parameters directly from the state store, as fetching
	// via tmcore.ConsensusParameters also tries fetching latest uncommitted
	// block which wont work with the archive node setup.
	consensusParams, err := tmstate.LoadConsensusParams(n.stateStore, tmHeight)
	if err != nil {
		return nil, fmt.Errorf("%w: tendermint: consensus params query failed: %s", consensusAPI.ErrVersionNotFound, err.Error())
	}
	meta, err := consensusParams.Marshal()
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to marshal consensus params: %w", err)
	}

	return &consensusAPI.Parameters{
		Height: tmHeight,
		Meta:   meta,
	}, nil
}

// Implements LightClientBackend.
func (n *commonNode) State() syncer.ReadSyncer {
	return n.mux.State().Storage()
}

// Implements LightClientBackend.
func (t *fullService) SubmitTxNoWait(ctx context.Context, tx *transaction.SignedTransaction) error {
	return t.broadcastTxRaw(cbor.Marshal(tx))
}

// Implements LightClientBackend.
func (srv *archiveService) SubmitTxNoWait(ctx context.Context, tx *transaction.SignedTransaction) error {
	return consensusAPI.ErrUnsupported
}
