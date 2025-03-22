package api

import (
	"context"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/consensus/genesis"
)

// LightService is a consensus light client service.
type LightService interface {
	service.BackgroundService

	LightProvider
	LightClient

	// GetStatus returns the current status overview.
	GetStatus() (*LightClientStatus, error)
}

// LightProvider is a consensus light provider interface.
//
// Warning: Light blocks returned by this provider are untrusted and should be
// verified before use.
type LightProvider interface {
	// LightBlock retrieves an untrusted light block at the specified height.
	LightBlock(ctx context.Context, height int64) (*LightBlock, error)
}

// LightClient is a consensus light client interface.
//
// Light blocks returned by this client are trusted and don't need to be
// verified before use.
type LightClient interface {
	// TrustedLightBlock returns trusted light block at the specified height.
	TrustedLightBlock(height int64) (*LightBlock, error)
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
	// Parameters are the backend agnostic consensus parameters.
	Parameters genesis.Parameters `json:"parameters"`
	// Meta contains the consensus backend specific consensus parameters.
	Meta []byte `json:"meta"`
}

// Evidence is evidence of a node's Byzantine behavior.
type Evidence struct {
	// Meta contains the consensus backend specific evidence.
	Meta []byte `json:"meta"`
}

// LightClientStatus is the current light client status overview.
type LightClientStatus struct {
	// LatestHeight is the height of the latest block.
	LatestHeight int64 `json:"latest_height"`
	// LatestHash is the hash of the latest block.
	LatestHash hash.Hash `json:"latest_hash"`
	// LatestTime is the timestamp of the latest block.
	LatestTime time.Time `json:"latest_time"`

	// OldestHeight is the height of the oldest block.
	OldestHeight int64 `json:"oldest_height"`
	// LatestHash is the hash of the oldest block.
	OldestHash hash.Hash `json:"oldest_hash"`
	// OldestTime is the timestamp of the oldest block.
	OldestTime time.Time `json:"oldest_time"`

	// PeersIDs are the light client provider peer identifiers.
	PeerIDs []string `json:"peer_ids"`
}
