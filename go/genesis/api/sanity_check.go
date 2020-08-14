package api

import (
	"fmt"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// SanityCheck does basic sanity checking on the contents of the genesis document.
func (d *Document) SanityCheck() error {
	if d.Height < 0 {
		return fmt.Errorf("genesis: sanity check failed: height must be >= 0")
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

	if err := d.EpochTime.SanityCheck(); err != nil {
		return err
	}
	if err := d.Registry.SanityCheck(d.EpochTime.Base, d.Staking.Ledger, d.Staking.Parameters.Thresholds, pkBlacklist); err != nil {
		return err
	}
	if err := d.RootHash.SanityCheck(); err != nil {
		return err
	}
	if err := d.Staking.SanityCheck(d.EpochTime.Base); err != nil {
		return err
	}
	if err := d.KeyManager.SanityCheck(); err != nil {
		return err
	}
	if err := d.Scheduler.SanityCheck(&d.Staking.TotalSupply); err != nil {
		return err
	}
	if err := d.Beacon.SanityCheck(); err != nil {
		return err
	}

	if d.HaltEpoch < d.EpochTime.Base {
		return fmt.Errorf("genesis: sanity check failed: halt epoch is in the past")
	}

	return nil
}
