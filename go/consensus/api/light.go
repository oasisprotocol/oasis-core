package api

import "context"

// LightClientBackend is the limited consensus interface used by light clients.
type LightClientBackend interface {
	// GetSignedHeader returns the signed header for a specific height.
	GetSignedHeader(ctx context.Context, height int64) (*SignedHeader, error)

	// GetValidatorSet returns the validator set for a specific height.
	GetValidatorSet(ctx context.Context, height int64) (*ValidatorSet, error)

	// GetParameters returns the consensus parameters for a specific height.
	GetParameters(ctx context.Context, height int64) (*Parameters, error)

	// TODO: Move SubmitEvidence etc. from Backend.
}

// SignedHeader is a signed consensus block header.
type SignedHeader struct {
	// Height contains the block height this header is for.
	Height int64 `json:"height"`
	// Meta contains the consensus backend specific signed header.
	Meta []byte `json:"meta"`
}

// ValidatorSet contains the validator set information.
type ValidatorSet struct {
	// Height contains the block height this validator set is for.
	Height int64 `json:"height"`
	// Meta contains the consensus backend specific validator set.
	Meta []byte `json:"meta"`
}

// Parameters are the consensus backend parameters.
type Parameters struct {
	// Height contains the block height these consensus parameters are for.
	Height int64 `json:"height"`

	// TODO: Consider also including consensus/genesis.Parameters which are backend-agnostic.

	// Meta contains the consensus backend specific consensus parameters.
	Meta []byte `json:"meta"`
}
