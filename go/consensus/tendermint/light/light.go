// Package light provides a light Tendermint consensus backend implementation.
package light

import (
	"context"

	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmtypes "github.com/tendermint/tendermint/types"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

// Client is a Tendermint consensus light client that talks with a remote oasis-node that is using
// the Tendermint consensus backend and verifies responses.
type Client interface {
	consensus.LightClientBackend

	// GetVerifiedSignedHeader returns a verified signed header.
	GetVerifiedSignedHeader(ctx context.Context, height int64) (*tmtypes.SignedHeader, error)

	// GetVerifiedValidatorSet returns a verified validator set.
	GetVerifiedValidatorSet(ctx context.Context, height int64) (*tmtypes.ValidatorSet, int64, error)

	// GetVerifiedParameters returns verified consensus parameters.
	GetVerifiedParameters(ctx context.Context, height int64) (*tmproto.ConsensusParams, error)
}
