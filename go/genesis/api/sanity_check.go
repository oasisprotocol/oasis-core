package api

import (
	"fmt"
	"strings"
	"time"
)

// SanityCheck does basic sanity checking on the contents of the genesis document.
func (d *Document) SanityCheck() error {
	if d.Height < 0 {
		return fmt.Errorf("genesis: sanity check failed: height must be >= 0")
	}

	if d.Time.After(time.Now()) {
		return fmt.Errorf("genesis: sanity check failed: time of genesis document is in the future")
	}

	if strings.TrimSpace(d.ChainID) == "" {
		return fmt.Errorf("genesis: sanity check failed: chain ID must not be empty")
	}

	var err error
	if err = d.EpochTime.SanityCheck(); err != nil {
		return err
	}
	if err = d.Registry.SanityCheck(d.EpochTime.Base); err != nil {
		return err
	}
	if err = d.RootHash.SanityCheck(); err != nil {
		return err
	}
	if err = d.Staking.SanityCheck(d.EpochTime.Base); err != nil {
		return err
	}
	if err = d.KeyManager.SanityCheck(); err != nil {
		return err
	}
	if err = d.Scheduler.SanityCheck(); err != nil {
		return err
	}
	if err = d.Beacon.SanityCheck(); err != nil {
		return err
	}
	if err = d.Consensus.SanityCheck(); err != nil {
		return err
	}

	if d.HaltEpoch < d.EpochTime.Base {
		return fmt.Errorf("genesis: sanity check failed: halt epoch is in the past")
	}

	return nil
}
