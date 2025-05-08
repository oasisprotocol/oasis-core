// Package api implements the vault backend API.
package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	// ModuleName is a unique module name for the vault module.
	ModuleName = "vault"
)

var (
	// ErrInvalidArgument is the error returned on malformed arguments.
	ErrInvalidArgument = errors.New(ModuleName, 1, "vault: invalid argument")
	// ErrNoSuchVault is the error returned when a vault does not exist.
	ErrNoSuchVault = errors.New(ModuleName, 2, "vault: no such vault")
	// ErrNoSuchState is the error returned when address state does not exist.
	ErrNoSuchState = errors.New(ModuleName, 3, "vault: no such state")
	// ErrInvalidNonce is the error returned when the vault nonce is invalid.
	ErrInvalidNonce = errors.New(ModuleName, 4, "vault: invalid nonce")
	// ErrForbidden is the error returned when an action is forbidden.
	ErrForbidden = errors.New(ModuleName, 5, "vault: forbidden")
	// ErrNoSuchAction is the error returned when an action does not exist.
	ErrNoSuchAction = errors.New(ModuleName, 6, "vault: no such action")
	// ErrUnsupportedAction is the error returned when an action is not supported.
	ErrUnsupportedAction = errors.New(ModuleName, 7, "vault: action not supported")
)

// Backend is a vault implementation.
type Backend interface {
	// Vaults returns all of the registered vaults.
	Vaults(ctx context.Context, height int64) ([]*Vault, error)

	// Vault returns information about the given vault.
	Vault(ctx context.Context, query *VaultQuery) (*Vault, error)

	// AddressState returns the state information for the given source address.
	AddressState(ctx context.Context, query *AddressQuery) (*AddressState, error)

	// PendingActions returns the list of pending actions for the given vault.
	PendingActions(ctx context.Context, query *VaultQuery) ([]*PendingAction, error)

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(ctx context.Context, height int64) (*Genesis, error)

	// ConsensusParameters returns the vault consensus parameters.
	ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error)

	// GetEvents returns the events at specified block height.
	GetEvents(ctx context.Context, height int64) ([]*Event, error)

	// WatchEvents returns a channel that produces a stream of Events.
	WatchEvents(ctx context.Context) (<-chan *Event, pubsub.ClosableSubscription, error)
}

// VaultQuery is a query for data about a given vault.
type VaultQuery struct {
	// Height is the query height.
	Height int64 `json:"height"`
	// Address is the vault address.
	Address staking.Address `json:"address"`
}

// AddressQuery is a query for data about a given address for the given vault.
type AddressQuery struct {
	// Height is the query height.
	Height int64 `json:"height"`
	// Vault is the vault address.
	Vault staking.Address `json:"vault"`
	// Address is the queried address.
	Address staking.Address `json:"address"`
}

// Genesis is the initial vault state for use in the genesis block.
type Genesis struct {
	// Parameters are the genesis consensus parameters.
	Parameters ConsensusParameters `json:"params"`

	// Vaults are the vaults.
	Vaults []*Vault `json:"vaults,omitempty"`
	// States are the per vault per-address states.
	States map[staking.Address]map[staking.Address]*AddressState `json:"states,omitempty"`
	// PendingActions are the per-vault pending actions.
	PendingActions map[staking.Address][]*PendingAction `json:"pending_actions,omitempty"`
}

// ConsensusParameters are the vault consensus parameters.
type ConsensusParameters struct {
	// Enabled specifies whether the vault service is enabled.
	Enabled bool `json:"enabled,omitempty"`

	// MaxAuthorityAddresses is the maximum number of addresses that can be configured for each
	// authority.
	MaxAuthorityAddresses uint8 `json:"max_authority_addresses,omitempty"`

	// GasCosts are the vault transaction gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`
}

// DefaultConsensusParameters are the default vault consensus parameters.
var DefaultConsensusParameters = ConsensusParameters{
	Enabled:               true,
	MaxAuthorityAddresses: 32,
	GasCosts:              DefaultGasCosts,
}

// ConsensusParameterChanges are allowed vault consensus parameter changes.
type ConsensusParameterChanges struct {
	// MaxAuthorityAddresses is the new maximum number of addresses that can be configured for each
	// authority.
	MaxAuthorityAddresses *uint8 `json:"max_authority_addresses,omitempty"`

	// GasCosts are the new gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`
}

// Apply applies changes to the given consensus parameters.
func (c *ConsensusParameterChanges) Apply(params *ConsensusParameters) error {
	if c.MaxAuthorityAddresses != nil {
		params.MaxAuthorityAddresses = *c.MaxAuthorityAddresses
	}
	if c.GasCosts != nil {
		params.GasCosts = c.GasCosts
	}
	return nil
}
