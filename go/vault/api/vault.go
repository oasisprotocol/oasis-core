package api

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var _ prettyprint.PrettyPrinter = (*Authority)(nil)

// State is the vault state.
type State uint8

const (
	StateSuspended = 0
	StateActive    = 1
)

// Vault contains metadata about a vault.
type Vault struct {
	// Creator is the address of the vault creator.
	Creator staking.Address `json:"creator"`
	// ID is the unique per-creator identifier of the vault.
	ID uint64 `json:"id"`
	// State is the vault state.
	State State `json:"state"`
	// Nonce is the nonce to use for the next action.
	Nonce uint64 `json:"nonce,omitempty"`

	// AdminAuthority specifies the vault's admin authority.
	AdminAuthority Authority `json:"admin_authority"`
	// SuspendAuthority specifies the vault's suspend authority.
	SuspendAuthority Authority `json:"suspend_authority"`
}

// NewVaultAddress returns the address for the vault.
func NewVaultAddress(creator staking.Address, id uint64) staking.Address {
	return staking.NewModuleAddress(ModuleName, fmt.Sprintf("vault.%s.%d", creator, id))
}

// Address returns the address for the vault.
func (v *Vault) Address() staking.Address {
	return NewVaultAddress(v.Creator, v.ID)
}

// IsActive returns true iff the vault is currently active (processing withdrawals).
func (v *Vault) IsActive() bool {
	return v.State == StateActive
}

// AuthoritiesContain returns true iff any of the vault's authorities contain the address.
func (v *Vault) AuthoritiesContain(addr staking.Address) bool {
	for _, auth := range v.Authorities() {
		if auth.Contains(addr) {
			return true
		}
	}
	return false
}

// Authorities returns the list of all vault authorities.
func (v *Vault) Authorities() []*Authority {
	return []*Authority{
		&v.AdminAuthority,
		&v.SuspendAuthority,
	}
}

// Authority is the vault multisig authority.
type Authority struct {
	// Addresses are the addresses that can authorize an action.
	Addresses []staking.Address `json:"addresses"`
	// Threshold is the minimum number of addresses that must authorize an action.
	Threshold uint8 `json:"threshold"`
}

// Validate validates the authority configuration.
func (a *Authority) Validate(params *ConsensusParameters) error {
	if len(a.Addresses) == 0 {
		return fmt.Errorf("no addresses")
	}
	if a.Threshold == 0 {
		return fmt.Errorf("threshold cannot be zero")
	}
	if int(a.Threshold) > len(a.Addresses) {
		return fmt.Errorf("threshold is larger than the number of addresses")
	}
	if len(a.Addresses) > int(params.MaxAuthorityAddresses) {
		return fmt.Errorf("too many addresses in authority (max: %d got: %d)",
			params.MaxAuthorityAddresses, len(a.Addresses))
	}

	// Ensure no duplicate addresses.
	addressSet := make(map[staking.Address]struct{})
	for _, addr := range a.Addresses {
		if _, ok := addressSet[addr]; ok {
			return fmt.Errorf("duplicate address in authority: %s", addr)
		}
		addressSet[addr] = struct{}{}
	}
	return nil
}

// Contains checks whether the authority contains the given address.
func (a *Authority) Contains(address staking.Address) bool {
	return slices.Contains(a.Addresses, address)
}

// Verify checks whether the passed addresses are sufficient to authorize an action.
func (a *Authority) Verify(addresses []staking.Address) bool {
	addressSet := make(map[staking.Address]struct{})
	for _, addr := range a.Addresses {
		addressSet[addr] = struct{}{}
	}
	var count int
	for _, addr := range addresses {
		if _, ok := addressSet[addr]; !ok {
			continue // Ignore unknown addresses.
		}
		// Make sure we don't count duplicate addresses.
		delete(addressSet, addr)

		count++
		if count >= int(a.Threshold) {
			return true
		}
	}
	return false
}

// PrettyPrint writes a pretty-printed representation of Authority to the given writer.
func (a Authority) PrettyPrint(_ context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sAddresses:\n", prefix)
	for _, addr := range a.Addresses {
		fmt.Fprintf(w, "%s  - %s\n", prefix, addr)
	}
	fmt.Fprintf(w, "%sThreshold: %d\n", prefix, a.Threshold)
}

// PrettyType returns a representation of Authority that can be used for pretty printing.
func (a Authority) PrettyType() (interface{}, error) {
	return a, nil
}
