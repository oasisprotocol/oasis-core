package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// LightClientBackend is the limited consensus interface used by light clients.
type LightClientBackend interface {
	// GetLightBlock returns a light version of the consensus layer block that can be used for light
	// client verification.
	GetLightBlock(ctx context.Context, height int64) (*LightBlock, error)

	// GetParameters returns the consensus parameters for a specific height.
	GetParameters(ctx context.Context, height int64) (*Parameters, error)

	// State returns a MKVS read syncer that can be used to read consensus state from a remote node
	// and verify it against the trusted local root.
	State() syncer.ReadSyncer

	// SubmitTxNoWait submits a signed consensus transaction, but does not wait for the transaction
	// to be included in a block. Use SubmitTx if you need to wait for execution.
	SubmitTxNoWait(ctx context.Context, tx *transaction.SignedTransaction) error

	// SubmitEvidence submits evidence of misbehavior.
	SubmitEvidence(ctx context.Context, evidence *Evidence) error
}

// LightBlock is a light consensus block suitable for syncing light clients.
type LightBlock struct {
	// Height contains the block height.
	Height int64 `json:"height"`
	// Meta contains the consensus backend specific light block.
	Meta []byte `json:"meta"`
}

// Parameters are the consensus backend parameters.
type Parameters struct {
	// Height contains the block height these consensus parameters are for.
	Height int64 `json:"height"`
	// Meta contains the consensus backend specific consensus parameters.
	Meta []byte `json:"meta"`

	// TODO: Consider also including consensus/genesis.Parameters which are backend-agnostic.
}

// Evidence is evidence of a node's Byzantine behavior.
type Evidence struct {
	// Meta contains the consensus backend specific evidence.
	Meta []byte `json:"meta"`
}
