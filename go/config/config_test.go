package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoteStorageValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      NodeMode
		validator bool
		mustErr   bool
	}{
		{name: "client", mode: ModeClient},
		{name: "observer", mode: ModeObserver},
		{name: "validator", mode: ModeValidator, mustErr: true},
		{name: "compute", mode: ModeCompute, mustErr: true},
		{name: "keymanager", mode: ModeKeyManager, mustErr: true},
		{name: "seed", mode: ModeSeed, mustErr: true},
		{name: "archive", mode: ModeArchive, mustErr: true},
		{name: "consensus validator and observer", mode: ModeObserver, validator: true, mustErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Mode = tc.mode
			cfg.Consensus.LocalStorage = false
			cfg.Consensus.Validator = tc.validator

			err := cfg.Validate()
			if tc.mustErr {
				require.ErrorContains(t, err, "local storage not available in specified mode")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
