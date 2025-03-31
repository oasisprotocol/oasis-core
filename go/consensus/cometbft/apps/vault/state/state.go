package state

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

var (
	// vaultKeyFmt is the key format used for storing the vault data.
	//
	// Value is a CBOR-serialized Vault.
	vaultKeyFmt = consensus.KeyFormat.New(0x30, &staking.Address{})

	// addressStateKeyFmt is the key format used for storing per-vault per-address state.
	//
	// Value is CBOR-serialized AddressState.
	addressStateKeyFmt = consensus.KeyFormat.New(0x31, &staking.Address{}, &staking.Address{})

	// pendingActionsKeyFmt is the key format used for storing per-vault pending actions.
	//
	// Value is CBOR-serialized PendingAction.
	pendingActionsKeyFmt = consensus.KeyFormat.New(0x32, &staking.Address{}, uint64(0))

	// parametersKeyFmt is the key format used for storing consensus parameters.
	//
	// Value is CBOR-serialized vault.ConsensusParameters.
	parametersKeyFmt = consensus.KeyFormat.New(0x33)
)

// ImmutableState is an immutable vault state wrapper.
type ImmutableState struct {
	is *api.ImmutableState
}

// NewImmutableState creates a new immutable vault state wrapper.
func NewImmutableState(tree mkvs.ImmutableKeyValueTree) *ImmutableState {
	return &ImmutableState{
		is: api.NewImmutableState(tree),
	}
}

// NewImmutableStateAt creates a new immutable vault state wrapper
// using the provided application query state and version.
func NewImmutableStateAt(ctx context.Context, state api.ApplicationQueryState, version int64) (*ImmutableState, error) {
	is, err := api.NewImmutableStateAt(ctx, state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{is}, nil
}

// Vaults looks up all vaults.
func (s *ImmutableState) Vaults(ctx context.Context) ([]*vault.Vault, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var vaults []*vault.Vault
	for it.Seek(vaultKeyFmt.Encode()); it.Valid(); it.Next() {
		var vaultAddr staking.Address
		if !vaultKeyFmt.Decode(it.Key(), &vaultAddr) {
			break
		}

		var v vault.Vault
		if err := cbor.Unmarshal(it.Value(), &v); err != nil {
			return nil, api.UnavailableStateError(err)
		}
		vaults = append(vaults, &v)
	}
	if it.Err() != nil {
		return nil, api.UnavailableStateError(it.Err())
	}
	return vaults, nil
}

func (s *ImmutableState) Vault(ctx context.Context, address staking.Address) (*vault.Vault, error) {
	raw, err := s.is.Get(ctx, vaultKeyFmt.Encode(address))
	if err != nil {
		return nil, api.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, vault.ErrNoSuchVault
	}

	var v vault.Vault
	if err := cbor.Unmarshal(raw, &v); err != nil {
		return nil, api.UnavailableStateError(err)
	}
	return &v, nil
}

func (s *ImmutableState) AddressState(ctx context.Context, vaultAddr staking.Address, address staking.Address) (*vault.AddressState, error) {
	raw, err := s.is.Get(ctx, addressStateKeyFmt.Encode(vaultAddr, address))
	if err != nil {
		return nil, api.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, vault.ErrNoSuchState
	}

	var state vault.AddressState
	if err := cbor.Unmarshal(raw, &state); err != nil {
		return nil, api.UnavailableStateError(err)
	}
	return &state, nil
}

func (s *ImmutableState) AddressStates(ctx context.Context, vaultAddr staking.Address) (map[staking.Address]*vault.AddressState, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	states := make(map[staking.Address]*vault.AddressState)
	for it.Seek(addressStateKeyFmt.Encode(vaultAddr)); it.Valid(); it.Next() {
		var (
			decVaultAddr staking.Address
			decAddr      staking.Address
		)
		if !addressStateKeyFmt.Decode(it.Key(), &decVaultAddr, &decAddr) || !vaultAddr.Equal(decVaultAddr) {
			break
		}

		var state vault.AddressState
		if err := cbor.Unmarshal(it.Value(), &state); err != nil {
			return nil, api.UnavailableStateError(err)
		}
		states[decAddr] = &state
	}
	if it.Err() != nil {
		return nil, api.UnavailableStateError(it.Err())
	}
	return states, nil
}

func (s *ImmutableState) PendingAction(ctx context.Context, vaultAddr staking.Address, nonce uint64) (*vault.PendingAction, error) {
	raw, err := s.is.Get(ctx, pendingActionsKeyFmt.Encode(vaultAddr, nonce))
	if err != nil {
		return nil, api.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, vault.ErrNoSuchAction
	}

	var pa vault.PendingAction
	if err := cbor.Unmarshal(raw, &pa); err != nil {
		return nil, api.UnavailableStateError(err)
	}
	return &pa, nil
}

func (s *ImmutableState) PendingActions(ctx context.Context, vaultAddr staking.Address) ([]*vault.PendingAction, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var actions []*vault.PendingAction
	for it.Seek(pendingActionsKeyFmt.Encode(vaultAddr)); it.Valid(); it.Next() {
		var decVaultAddr staking.Address
		if !pendingActionsKeyFmt.Decode(it.Key(), &decVaultAddr) || !decVaultAddr.Equal(vaultAddr) {
			break
		}

		var pa vault.PendingAction
		if err := cbor.Unmarshal(it.Value(), &pa); err != nil {
			return nil, api.UnavailableStateError(err)
		}
		actions = append(actions, &pa)
	}
	if it.Err() != nil {
		return nil, api.UnavailableStateError(it.Err())
	}
	return actions, nil
}

// ConsensusParameters returns the vault consensus parameters.
func (s *ImmutableState) ConsensusParameters(ctx context.Context) (*vault.ConsensusParameters, error) {
	raw, err := s.is.Get(ctx, parametersKeyFmt.Encode())
	if err != nil {
		return nil, api.UnavailableStateError(err)
	}
	if raw == nil {
		return &vault.ConsensusParameters{}, nil
	}

	var params vault.ConsensusParameters
	if err = cbor.Unmarshal(raw, &params); err != nil {
		return nil, api.UnavailableStateError(err)
	}
	return &params, nil
}

// MutableState is a mutable consensus state wrapper.
type MutableState struct {
	*ImmutableState

	ms mkvs.KeyValueTree
}

// NewMutableState creates a new mutable vault state wrapper.
func NewMutableState(tree mkvs.KeyValueTree) *MutableState {
	return &MutableState{
		ImmutableState: NewImmutableState(tree),
		ms:             tree,
	}
}

// CreateVault creates a new vault.
//
// NOTE: This operation performs multiple actions so it should be wrapped in a transaction.
func (s *MutableState) CreateVault(ctx context.Context, vlt *vault.Vault) error {
	addr := vlt.Address()

	// Sanity check to make sure that the vault doesn't already exist.
	if _, err := s.Vault(ctx, addr); err == nil {
		return vault.ErrInvalidArgument
	}
	if err := s.SetVault(ctx, vlt); err != nil {
		return err
	}

	// Configure withdraw hook on the vault's account that was just created.
	stakeState := stakingState.NewMutableState(s.ms)
	err := stakeState.SetAccountHook(ctx, addr, staking.HookKindWithdraw, &staking.HookDestination{
		Module: vault.ModuleName,
	})
	if err != nil {
		return err
	}

	return nil
}

// SetVault updates a vault descriptor.
func (s *MutableState) SetVault(ctx context.Context, vault *vault.Vault) error {
	addr := vault.Address()
	err := s.ms.Insert(ctx, vaultKeyFmt.Encode(&addr), cbor.Marshal(vault))
	return api.UnavailableStateError(err)
}

// SetAddressState sets the address state.
func (s *MutableState) SetAddressState(ctx context.Context, vaultAddr staking.Address, addr staking.Address, state *vault.AddressState) error {
	err := s.ms.Insert(ctx, addressStateKeyFmt.Encode(vaultAddr, addr), cbor.Marshal(state))
	return api.UnavailableStateError(err)
}

// SetPendingAction updates the pending action.
func (s *MutableState) SetPendingAction(ctx context.Context, vaultAddr staking.Address, action *vault.PendingAction) error {
	err := s.ms.Insert(ctx, pendingActionsKeyFmt.Encode(vaultAddr, action.Nonce), cbor.Marshal(action))
	return api.UnavailableStateError(err)
}

// RemovePendingAction removes the pending action with the given nonce.
func (s *MutableState) RemovePendingAction(ctx context.Context, vaultAddr staking.Address, nonce uint64) error {
	err := s.ms.Remove(ctx, pendingActionsKeyFmt.Encode(vaultAddr, nonce))
	return api.UnavailableStateError(err)
}

// SetConsensusParameters sets vault consensus parameters.
//
// NOTE: This method must only be called from InitChain/EndBlock contexts.
func (s *MutableState) SetConsensusParameters(ctx context.Context, params *vault.ConsensusParameters) error {
	if err := s.is.CheckContextMode(ctx, []api.ContextMode{api.ContextInitChain, api.ContextEndBlock}); err != nil {
		return err
	}
	err := s.ms.Insert(ctx, parametersKeyFmt.Encode(), cbor.Marshal(params))
	return api.UnavailableStateError(err)
}
