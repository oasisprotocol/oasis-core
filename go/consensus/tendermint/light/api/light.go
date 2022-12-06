// Package api provides a light Tendermint consensus backend API.
package api

import (
	"context"

	tmlight "github.com/tendermint/tendermint/light"
	tmlightprovider "github.com/tendermint/tendermint/light/provider"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmtypes "github.com/tendermint/tendermint/types"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

// ClientService is a Tendermint consensus light client service.
type ClientService interface {
	consensus.LightService

	Client
}

// Client is a Tendermint consensus light client that talks with remote oasis-nodes that are using
// the Tendermint consensus backend and verifies responses.
type Client interface {
	consensus.LightClient

	// GetVerifiedLightBlock returns a verified light block.
	GetVerifiedLightBlock(ctx context.Context, height int64) (*tmtypes.LightBlock, error)

	// GetVerifiedParameters returns verified consensus parameters.
	GetVerifiedParameters(ctx context.Context, height int64) (*tmproto.ConsensusParams, error)
}

// Provider is a Tendermint light client provider.
type Provider interface {
	tmlightprovider.Provider
	consensus.LightClient

	// Initialized returns a channel that is closed when the provider is initialized.
	Initialized() <-chan struct{}

	// PeerID returns the identifier of the peer backing the provider.
	PeerID() string
}

// ClientConfig is the configuration for the light client.
type ClientConfig struct {
	// GenesisDocument is the Tendermint genesis document.
	GenesisDocument *tmtypes.GenesisDoc

	// TrustOptions are Tendermint light client trust options.
	TrustOptions tmlight.TrustOptions
}
