package api

import (
	"fmt"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// SanityCheck does basic sanity checking on the contents of the genesis document.
func (d *Document) SanityCheck() error {
	if d.Height < 1 {
		return fmt.Errorf("genesis: sanity check failed: height must be >= 1")
	}

	if strings.TrimSpace(d.ChainID) == "" {
		return fmt.Errorf("genesis: sanity check failed: chain ID must not be empty")
	}

	if err := d.Consensus.SanityCheck(); err != nil {
		return err
	}
	pkBlacklist := make(map[signature.PublicKey]bool)
	for _, v := range d.Consensus.Parameters.PublicKeyBlacklist {
		pkBlacklist[v] = true
	}

	if err := d.Beacon.SanityCheck(); err != nil {
		return err
	}
	epoch := d.Beacon.Base // Note: d.Height has no easy connection to the epoch.

	escrows := make(map[staking.Address]*staking.EscrowAccount)

	if err := d.Registry.SanityCheck(
		d.Time,
		uint64(d.Height),
		epoch,
		pkBlacklist,
		escrows,
	); err != nil {
		return err
	}
	if err := d.RootHash.SanityCheck(); err != nil {
		return err
	}
	if err := d.Staking.SanityCheck(epoch); err != nil {
		return err
	}
	if err := d.KeyManager.SanityCheck(); err != nil {
		return err
	}
	if err := d.Scheduler.SanityCheck(&d.Staking.TotalSupply, d.Scheduler.Parameters.VotingPowerDistribution); err != nil {
		return err
	}
	if err := d.Governance.SanityCheck(epoch, &d.Staking.GovernanceDeposits); err != nil {
		return err
	}
	if err := d.Vault.SanityCheck(); err != nil {
		return err
	}

	if d.Staking.Parameters.DebugBypassStake {
		return nil
	}
	return staking.SanityCheckStake(d.Staking.Ledger, escrows, d.Staking.Parameters.Thresholds, true)
}
